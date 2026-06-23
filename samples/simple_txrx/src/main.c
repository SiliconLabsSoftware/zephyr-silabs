/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/drivers/gpio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

#include "sl_rail.h"
#include "rail_config.h"
#include "sl_rail_util_pa_conversions.h"

LOG_MODULE_REGISTER(app);

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
	sl_rail_handle_t rail_handle;
	struct k_event events;
	struct k_mutex tx_lock;
	int channel;
	const uint8_t *payload;
	int payload_len;
} app_ctx;

void rx_packets(sl_rail_handle_t rail_handle)
{
	uint8_t rx_frame[32];
	sl_rail_rx_packet_handle_t handle;
	sl_rail_rx_packet_info_t info;
	sl_rail_status_t status;

	for (;;) {
		handle = sl_rail_get_rx_packet_info(rail_handle,
						    SL_RAIL_RX_PACKET_HANDLE_OLDEST_COMPLETE,
						    &info);
		if (handle == SL_RAIL_RX_PACKET_HANDLE_INVALID) {
			return;
		}
		if (info.packet_bytes < sizeof(rx_frame)) {
			sl_rail_copy_rx_packet(rail_handle, rx_frame, &info);
		}
		status = sl_rail_release_rx_packet(rail_handle, handle);
		if (status) {
			LOG_ERR("sl_rail_release_rx_packet(): 0x%x", status);
		}
		if (info.packet_bytes < sizeof(rx_frame)) {
			LOG_HEXDUMP_INF(rx_frame, info.packet_bytes, "rx data:");
		} else {
			LOG_INF("rx: skip large packet");
		}
		gpio_pin_set_dt(&led_rx, 0);
	}
}

void tx_packet(sl_rail_handle_t rail_handle, int channel, const uint8_t *payload, int len)
{
	sl_rail_status_t status;
	int ret;

	ret = sl_rail_write_tx_fifo(rail_handle, payload, len, true);
	if (ret != len) {
		LOG_ERR("sl_rail_write_tx_fifo(): 0x%x", ret);
		return;
	}
	gpio_pin_set_dt(&led_tx, 1);
	status = sl_rail_start_tx(rail_handle, channel, SL_RAIL_TX_OPTIONS_DEFAULT, NULL);
	if (status) {
		LOG_ERR("sl_rail_start_tx(): 0x%x", status);
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

void rail_on_event(sl_rail_handle_t rail_handle, sl_rail_events_t events)
{
	sl_rail_status_t status;

	if (events & SL_RAIL_EVENTS_RX_COMPLETION) {
		if (events & SL_RAIL_EVENT_RX_PACKET_RECEIVED) {
			gpio_pin_set_dt(&led_rx, 1);
			sl_rail_hold_rx_packet(rail_handle);
			k_event_post(&app_ctx.events, EV_RAIL_RX);
		} else {
			LOG_ERR("radio rx error: %08llx", events);
		}
	}

	if (events & SL_RAIL_EVENTS_TX_COMPLETION) {
		if (!(events & SL_RAIL_EVENT_TX_PACKET_SENT)) {
			LOG_ERR("radio tx error: %08llx", events);
		}
		gpio_pin_set_dt(&led_tx, 0);
	}

	if (events & SL_RAIL_EVENTS_TXACK_COMPLETION) {
		/* We do not configure Tx ack. Catch the event anyway */
		LOG_INF("received ack completion");
	}

	if (events & SL_RAIL_EVENT_CAL_NEEDED) {
		status = sl_rail_calibrate(rail_handle, NULL, SL_RAIL_CAL_ALL_PENDING);
		if (status) {
			LOG_ERR("sl_rail_calibrate(): 0x%x", status);
		}
	}
}

static void rail_on_rf_ready(sl_rail_handle_t rail_handle)
{
	LOG_INF("radio is ready");
}

static void rail_on_channel_config(sl_rail_handle_t rail_handle,
				   const sl_rail_channel_config_entry_t *entry)
{
	sl_rail_util_pa_on_channel_config_change(rail_handle, entry);
}

static sl_rail_handle_t rail_init(void)
{
	static SL_RAIL_DECLARE_FIFO_BUFFER(tx_fifo, 256);
	static SL_RAIL_DECLARE_FIFO_BUFFER(rx_fifo, 256);
	sl_rail_config_t rail_config = {
		.events_callback = &rail_on_event,
		.rx_packet_queue_entries = sl_rail_builtin_rx_packet_queue_entries,
		.p_rx_packet_queue = sl_rail_builtin_rx_packet_queue_ptr,
		.rx_fifo_bytes = sizeof(rx_fifo),
		.p_rx_fifo_buffer = rx_fifo,
		.tx_fifo_bytes = sizeof(tx_fifo),
		.tx_fifo_init_bytes = 0,
		.p_tx_fifo_buffer = tx_fifo,
	};
	sl_rail_tx_data_config_t tx_data_config = {
		.tx_source = SL_RAIL_TX_DATA_SOURCE_PACKET_DATA,
		.tx_method = SL_RAIL_DATA_METHOD_PACKET_MODE,
	};
	sl_rail_rx_data_config_t rx_data_config = {
		.rx_source = SL_RAIL_RX_DATA_SOURCE_PACKET_DATA,
		.rx_method = SL_RAIL_DATA_METHOD_PACKET_MODE,
	};
	sl_rail_state_transitions_t transitions = {
		.success = SL_RAIL_RF_STATE_RX,
		.error   = SL_RAIL_RF_STATE_RX,
	};
	sl_rail_handle_t rail_handle = SL_RAIL_EFR32_HANDLE;
	const sl_rail_channel_config_t *channel_config =
		(const sl_rail_channel_config_t *)channelConfigs[0];
	sl_rail_status_t status;

	status = sl_rail_init(&rail_handle, &rail_config, &rail_on_rf_ready);
	if (status) {
		LOG_ERR("sl_rail_init(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_config_tx_data(rail_handle, &tx_data_config);
	if (status) {
		LOG_ERR("sl_rail_config_tx_data(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_config_rx_data(rail_handle, &rx_data_config);
	if (status) {
		LOG_ERR("sl_rail_config_rx_data(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_config_channels(rail_handle, channel_config, &rail_on_channel_config);
	if (status) {
		LOG_ERR("sl_rail_config_channels(): 0x%x", status);
		return NULL;
	}
	app_ctx.channel = sl_rail_get_first_channel(rail_handle, channel_config);
	if (app_ctx.channel == SL_RAIL_CHANNEL_INVALID) {
		LOG_ERR("invalid sl_rail_get_first_channel()");
		return NULL;
	}
	status = sl_rail_prepare_channel(rail_handle, app_ctx.channel);
	if (status) {
		LOG_ERR("sl_rail_prepare_channel(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_set_pti_protocol(rail_handle, SL_RAIL_PTI_PROTOCOL_CUSTOM);
	if (status) {
		LOG_ERR("sl_rail_set_pti_protocol(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_config_cal(rail_handle, SL_RAIL_CAL_TEMP | SL_RAIL_CAL_ONETIME);
	if (status) {
		LOG_ERR("sl_rail_config_cal(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_config_events(rail_handle, SL_RAIL_EVENTS_ALL,
				       SL_RAIL_EVENTS_RX_COMPLETION |
				       SL_RAIL_EVENTS_TX_COMPLETION |
				       SL_RAIL_EVENTS_TXACK_COMPLETION |
				       SL_RAIL_EVENT_CAL_NEEDED);
	if (status) {
		LOG_ERR("sl_rail_config_events(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_set_tx_transitions(rail_handle, &transitions);
	if (status) {
		LOG_ERR("sl_rail_set_tx_transitions(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_set_rx_transitions(rail_handle, &transitions);
	if (status) {
		LOG_ERR("sl_rail_set_rx_transitions(): 0x%x", status);
		return NULL;
	}
	status = sl_rail_util_pa_post_init(rail_handle, SL_RAIL_TX_PA_MODE_2P4_GHZ);
	if (status) {
		LOG_ERR("sl_rail_util_pa_post_init(): 0x%x", status);
		return NULL;
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
	sl_rail_status_t status;
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
	app_ctx.payload = default_payload;
	app_ctx.payload_len = sizeof(default_payload);

	if (app_ctx.rail_handle == NULL) {
		return 1;
	}

	ret = sl_rail_set_fixed_length(app_ctx.rail_handle, app_ctx.payload_len);
	if (ret != app_ctx.payload_len) {
		LOG_ERR("sl_rail_set_fixed_length(): 0x%x", ret);
		return 1;
	}
	status = sl_rail_start_rx(app_ctx.rail_handle, app_ctx.channel, NULL);
	if (status) {
		LOG_ERR("sl_rail_start_rx(): 0x%x", status);
		return 1;
	}

#ifdef CONFIG_PM
	sl_rail_timer_sync_config_t timer_sync_config = SL_RAIL_TIMER_SYNC_DEFAULT;

	status = sl_rail_config_sleep(app_ctx.rail_handle, &timer_sync_config);
	if (status) {
		LOG_ERR("sl_rail_config_sleep(): 0x%x", status);
		return 1;
	}

	status = sl_rail_init_power_manager();
	if (status) {
		LOG_ERR("sl_rail_init_power_manager(): 0x%x", status);
		return 1;
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
