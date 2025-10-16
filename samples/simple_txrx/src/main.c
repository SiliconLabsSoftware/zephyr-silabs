/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/drivers/gpio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

#include "rail.h"
#include "rail_config.h"
#include "pa_conversions_efr32.h"

LOG_MODULE_REGISTER(app);

#ifdef RAIL0_CHANNEL_GROUP_1_PROFILE_WISUN_OFDM
#  if !defined(HARDWARE_BOARD_HAS_EFF)
	BUILD_ASSERT(SL_RAIL_UTIL_PA_SELECTION_SUBGHZ == RAIL_TX_POWER_MODE_OFDM_PA,
		     "Please use the OFDM PA settings in the sl_rail_util_pa_config.h "
		     "for OFDM phys");
#  endif
#  if defined(HARDWARE_BOARD_HAS_EFF) && RAIL_SUPPORTS_EFF
	BUILD_ASSERT(SL_RAIL_UTIL_PA_SELECTION_SUBGHZ >= RAIL_TX_POWER_MODE_OFDM_PA_EFF_30DBM,
		     "Please use the OFDM PA for EFF settings in the sl_rail_util_pa_config.h "
		     "for OFDM phys");
#  endif
#endif

static const struct gpio_dt_spec sw0 = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);
static const struct gpio_dt_spec led_rx = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#if DT_NODE_EXISTS(DT_ALIAS(led1))
static const struct gpio_dt_spec led_tx = GPIO_DT_SPEC_GET(DT_ALIAS(led1), gpios);
#else
static const struct gpio_dt_spec led_tx = led_rx;
#endif

enum {
	EV_RAIL_RX     = BIT(0),
	EV_BTN_PRESSED = BIT(1),
};

struct {
	RAIL_Handle_t rail_handle;
	struct k_event events;
	struct k_mutex tx_lock;
	int channel;
	const uint8_t *payload;
	int payload_len;
} app_ctx;

void rx_packets(RAIL_Handle_t rail_handle)
{
	uint8_t rx_frame[32];
	RAIL_RxPacketHandle_t handle;
	RAIL_RxPacketInfo_t info;
	RAIL_Status_t status;

	for (;;) {
		handle = RAIL_GetRxPacketInfo(rail_handle, RAIL_RX_PACKET_HANDLE_OLDEST_COMPLETE,
					      &info);
		if (handle == RAIL_RX_PACKET_HANDLE_INVALID) {
			return;
		}
		if (info.packetBytes < sizeof(rx_frame)) {
			RAIL_CopyRxPacket(rx_frame, &info);
		}
		status = RAIL_ReleaseRxPacket(rail_handle, handle);
		if (status) {
			LOG_ERR("RAIL_ReleaseRxPacket(): %d", status);
		}
		if (info.packetBytes < sizeof(rx_frame)) {
			LOG_HEXDUMP_INF(rx_frame, info.packetBytes, "rx data:");
		} else {
			LOG_INF("rx: skip large packet");
		}
		gpio_pin_set_dt(&led_rx, 0);
	}
}

void tx_packet(RAIL_Handle_t rail_handle, int channel, const uint8_t *payload, int len)
{
	RAIL_Status_t status;
	int ret;

	ret = RAIL_WriteTxFifo(rail_handle, payload, len, true);
	if (ret != len) {
		LOG_ERR("RAIL_WriteTxFifo(): %d", ret);
		return;
	}
	gpio_pin_set_dt(&led_tx, 1);
	status = RAIL_StartTx(rail_handle, channel, RAIL_TX_OPTIONS_DEFAULT, NULL);
	if (status) {
		LOG_ERR("RAIL_StartTx(): %d ", status);
	}
	LOG_HEXDUMP_INF(payload, len, "tx data:");
}

void btn_pressed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	/* This function is called from an ISR context. So, transfer the real
	 * processing to the main loop.
	 */
	k_event_post(&app_ctx.events, EV_BTN_PRESSED);
}

void cli_send(const struct shell *sh, size_t argc, char **argv)
{
	k_mutex_lock(&app_ctx.tx_lock, K_FOREVER);
	tx_packet(app_ctx.rail_handle, app_ctx.channel, app_ctx.payload, app_ctx.payload_len);
	k_mutex_unlock(&app_ctx.tx_lock);
}

void rail_on_event(RAIL_Handle_t rail_handle, RAIL_Events_t events)
{
	RAIL_Status_t status;

	if (events & RAIL_EVENTS_RX_COMPLETION) {
		if (events & RAIL_EVENT_RX_PACKET_RECEIVED) {
			gpio_pin_set_dt(&led_rx, 1);
			RAIL_HoldRxPacket(rail_handle);
			k_event_post(&app_ctx.events, EV_RAIL_RX);
		} else {
			LOG_ERR("radio rx error: %08llx", events);
		}
	}

	if (events & RAIL_EVENTS_TX_COMPLETION) {
		if (!(events & RAIL_EVENT_TX_PACKET_SENT)) {
			LOG_ERR("radio tx error: %08llx", events);
		}
		gpio_pin_set_dt(&led_tx, 0);
	}

	if (events & RAIL_EVENTS_TXACK_COMPLETION) {
		/* We do not configure Tx ack. Catch the event anyway */
		LOG_INF("received ack completion");
	}

	if (events & RAIL_EVENT_CAL_NEEDED) {
		status = RAIL_Calibrate(rail_handle, NULL, RAIL_CAL_ALL_PENDING);
		if (status) {
			LOG_ERR("RAIL_Calibrate(): %d", status);
		}
	}
}

static void rail_on_rf_ready(RAIL_Handle_t rail_handle)
{
	LOG_INF("radio is ready");
}

static void rail_on_channel_config(RAIL_Handle_t rail_handle,
				   const RAIL_ChannelConfigEntry_t *entry)
{
	sl_rail_util_pa_on_channel_config_change(rail_handle, entry);
}

static RAIL_Handle_t rail_init(void)
{
	static uint8_t tx_fifo[256] __aligned(4);
	RAIL_Config_t rail_config = {
		.eventsCallback = &rail_on_event,
	};
	RAIL_DataConfig_t data_config = {
		.txSource = TX_PACKET_DATA,
		.rxSource = RX_PACKET_DATA,
		.txMethod = PACKET_MODE,
		.rxMethod = PACKET_MODE,
	};
	RAIL_StateTransitions_t transitions = {
		.success = RAIL_RF_STATE_RX,
		.error   = RAIL_RF_STATE_RX,
	};
	RAIL_Handle_t rail_handle;
	RAIL_Status_t status;
	int ret;

	rail_handle = RAIL_Init(&rail_config, &rail_on_rf_ready);
	if (!rail_handle) {
		LOG_ERR("RAIL_Init() failed");
	}
	status = RAIL_ConfigData(rail_handle, &data_config);
	if (status) {
		LOG_ERR("RAIL_ConfigData(): %d", status);
	}
	status = RAIL_ConfigChannels(rail_handle, channelConfigs[0], &rail_on_channel_config);
	if (status) {
		LOG_ERR("RAIL_ConfigChannels(): %d", status);
	}
	status = RAIL_SetPtiProtocol(rail_handle, RAIL_PTI_PROTOCOL_CUSTOM);
	if (status) {
		LOG_ERR("RAIL_SetPtiProtocol(): %d", status);
	}
	status = RAIL_ConfigCal(rail_handle, RAIL_CAL_TEMP | RAIL_CAL_ONETIME);
	if (status) {
		LOG_ERR("RAIL_ConfigCal(): %d", status);
	}
	status = RAIL_ConfigEvents(rail_handle, RAIL_EVENTS_ALL,
				   RAIL_EVENTS_RX_COMPLETION |
				   RAIL_EVENTS_TX_COMPLETION |
				   RAIL_EVENTS_TXACK_COMPLETION |
				   RAIL_EVENT_CAL_NEEDED);
	if (status) {
		LOG_ERR("RAIL_ConfigEvents(): %d", status);
	}
	status = RAIL_SetTxTransitions(rail_handle, &transitions);
	if (status) {
		LOG_ERR("RAIL_SetTxTransitions(): %d", status);
	}
	status = RAIL_SetRxTransitions(rail_handle, &transitions);
	if (status) {
		LOG_ERR("RAIL_SetRxTransitions(): %d", status);
	}
	ret = RAIL_SetTxFifo(rail_handle, tx_fifo, 0, sizeof(tx_fifo));
	if (ret != sizeof(tx_fifo)) {
		LOG_ERR("RAIL_SetTxFifo(): %d != %d", ret, sizeof(tx_fifo));
	}

	return rail_handle;
}

int main(void)
{
	static const uint8_t default_payload[] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};
	struct gpio_callback sw0_cb;
	RAIL_Status_t status;
	uint32_t events;
	int ret;

	k_event_init(&app_ctx.events);
	k_mutex_init(&app_ctx.tx_lock);
	gpio_pin_configure_dt(&led_tx, GPIO_OUTPUT_INACTIVE);
	gpio_pin_configure_dt(&led_rx, GPIO_OUTPUT_INACTIVE);
	gpio_pin_configure_dt(&sw0, GPIO_INPUT);
	gpio_pin_interrupt_configure_dt(&sw0, GPIO_INT_EDGE_TO_ACTIVE);
	gpio_init_callback(&sw0_cb, btn_pressed, BIT(sw0.pin));
	gpio_add_callback(sw0.port, &sw0_cb);

	sl_rail_util_pa_init();
	app_ctx.rail_handle = rail_init();
	app_ctx.channel = 0;
	app_ctx.payload = default_payload;
	app_ctx.payload_len = sizeof(default_payload);

	ret = RAIL_SetFixedLength(app_ctx.rail_handle, app_ctx.payload_len);
	if (ret != app_ctx.payload_len) {
		LOG_ERR("RAIL_SetFixedLength(): %d ", ret);
	}
	status = RAIL_StartRx(app_ctx.rail_handle, app_ctx.channel, NULL);
	if (status) {
		LOG_ERR("RAIL_StartRx(): %d ", status);
	}

#ifdef CONFIG_PM
	status = RAIL_InitPowerManager();
	if (status) {
		LOG_ERR("RAIL_InitPowerManager(): %d", status);
	}
#endif

	for (;;) {
		events = k_event_wait(&app_ctx.events, 0xFFFFFFFF, true, K_FOREVER);
		if (events & EV_RAIL_RX) {
			rx_packets(app_ctx.rail_handle);
		}
		if (events & EV_BTN_PRESSED) {
			k_mutex_lock(&app_ctx.tx_lock, K_FOREVER);
			tx_packet(app_ctx.rail_handle, app_ctx.channel,
				  app_ctx.payload, app_ctx.payload_len);
			k_mutex_unlock(&app_ctx.tx_lock);
		}
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(radio_cmds,
	SHELL_CMD_ARG(send, NULL, "Send a packet", cli_send, 1, 0),
	SHELL_SUBCMD_SET_END
);
SHELL_CMD_ARG_REGISTER(radio, &radio_cmds, "Radio control", NULL, 2, 0);
