/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/bluetooth.h>

#define DT_DRV_COMPAT silabs_bt_hci_siwx917
#define LOG_LEVEL     CONFIG_BT_HCI_DRIVER_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bt_hci_driver_siwg917);

#include "sl_wifi.h"
#include "sl_wifi_callback_framework.h"
#include "rsi_ble_common_config.h"
#include "rsi_ble.h"

static void bt_siwg917_resp_rcvd(uint16_t status, rsi_ble_event_rcp_rcvd_info_t *resp_buf);

struct hci_data {
	bt_hci_recv_t recv;
	rsi_data_packet_t rsi_data_packet;
};

static const sl_wifi_device_configuration_t network_config = {
	.boot_option = LOAD_NWP_FW,
	.mac_address = NULL,
	.band = SL_SI91X_WIFI_BAND_2_4GHZ,
	.region_code = DEFAULT_REGION,
	.boot_config = {
		.oper_mode = SL_SI91X_CLIENT_MODE,
		.coex_mode = SL_SI91X_BLE_MODE,
		.feature_bit_map =
			SL_SI91X_FEAT_SECURITY_OPEN |
			SL_SI91X_FEAT_WPS_DISABLE,
		.tcp_ip_feature_bit_map =
			SL_SI91X_TCP_IP_FEAT_DHCPV4_CLIENT |
			SL_SI91X_TCP_IP_FEAT_EXTENSION_VALID,
		.ext_tcp_ip_feature_bit_map = SL_SI91X_CONFIG_FEAT_EXTENSION_VALID,
		.custom_feature_bit_map = SL_SI91X_CUSTOM_FEAT_EXTENSION_VALID,
		.ext_custom_feature_bit_map =
			MEMORY_CONFIG |
			SL_SI91X_EXT_FEAT_XTAL_CLK |
			SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
			SL_SI91X_EXT_FEAT_BT_CUSTOM_FEAT_ENABLE,
		.config_feature_bit_map = SL_SI91X_ENABLE_ENHANCED_MAX_PSP,
		.bt_feature_bit_map =
			SL_SI91X_BT_RF_TYPE |
			SL_SI91X_ENABLE_BLE_PROTOCOL,
		.ble_feature_bit_map =
			SL_SI91X_BLE_MAX_NBR_PERIPHERALS(RSI_BLE_MAX_NBR_PERIPHERALS) |
			SL_SI91X_BLE_MAX_NBR_CENTRALS(RSI_BLE_MAX_NBR_CENTRALS) |
			SL_SI91X_BLE_MAX_NBR_ATT_SERV(RSI_BLE_MAX_NBR_ATT_SERV) |
			SL_SI91X_BLE_MAX_NBR_ATT_REC(RSI_BLE_MAX_NBR_ATT_REC) |
			SL_SI91X_BLE_PWR_INX(RSI_BLE_PWR_INX) |
			SL_SI91X_BLE_PWR_SAVE_OPTIONS(RSI_BLE_PWR_SAVE_OPTIONS) |
			SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE |
			SL_SI91X_FEAT_BLE_CUSTOM_FEAT_EXTENSION_VALID,
		.ble_ext_feature_bit_map =
			SL_SI91X_BLE_NUM_CONN_EVENTS(RSI_BLE_NUM_CONN_EVENTS) |
			SL_SI91X_BLE_NUM_REC_BYTES(RSI_BLE_NUM_REC_BYTES) |
			SL_SI91X_BLE_ENABLE_ADV_EXTN |
			SL_SI91X_BLE_AE_MAX_ADV_SETS(RSI_BLE_AE_MAX_ADV_SETS),
	}};

static int bt_siwg917_open(const struct device *dev, bt_hci_recv_t recv)
{
	struct hci_data *hci = dev->data;

	int status = sl_wifi_init(&network_config, NULL, sl_wifi_default_event_handler);
	status |= rsi_ble_enhanced_gap_extended_register_callbacks(RSI_BLE_ON_RCP_EVENT,
								   (void *)bt_siwg917_resp_rcvd);

	if (!status) {
		hci->recv = recv;
	}
	return status ? -EIO : 0;
}

static int bt_siwg917_send(const struct device *dev, struct net_buf *buf)
{
	struct hci_data *hci = dev->data;
	int sc = -EOVERFLOW;
	uint8_t packet_type = BT_HCI_H4_NONE;

	switch (bt_buf_get_type(buf)) {
	case BT_BUF_ACL_OUT:
		packet_type = BT_HCI_H4_ACL;
		break;
	case BT_BUF_CMD:
		packet_type = BT_HCI_H4_CMD;
		break;
	default:
		sc = -EINVAL;
		break;
	}

	if ((packet_type != BT_HCI_H4_NONE) && (buf->len < sizeof(hci->rsi_data_packet.data))) {
		net_buf_push_u8(buf, packet_type);
		memcpy(&hci->rsi_data_packet, buf->data, buf->len);
		sc = rsi_bt_driver_send_cmd(RSI_BLE_REQ_HCI_RAW, &hci->rsi_data_packet, NULL);
		/* TODO SILABS ZEPHYR Convert to errno. A common function from rsi/sl_status should
		 * be introduced
		 */
		if (sc) {
			LOG_ERR("BT command send failure: %d", sc);
			sc = -EIO;
		}
	}
	net_buf_unref(buf);
	return sc;
}

static void bt_siwg917_resp_rcvd(uint16_t status, rsi_ble_event_rcp_rcvd_info_t *resp_buf)
{
	const struct device *dev = DEVICE_DT_GET(DT_DRV_INST(0));
	struct hci_data *hci = dev->data;
	uint8_t packet_type = BT_HCI_H4_NONE;
	size_t len = 0;
	struct net_buf *buf = NULL;

	/* TODO SILABS ZEPHYR This horror expression is from the WiseConnect from the HCI example...
	 * No workaround have been found until now.
	 */
	memcpy(&packet_type, (resp_buf->data - 12), 1);
	switch (packet_type) {
	case BT_HCI_H4_EVT: {
		struct bt_hci_evt_hdr *hdr = (void *)resp_buf->data;

		len = hdr->len + sizeof(*hdr);
		buf = bt_buf_get_evt(hdr->evt, false, K_FOREVER);
		break;
	}
	case BT_HCI_H4_ACL: {
		struct bt_hci_acl_hdr *hdr = (void *)resp_buf->data;

		len = hdr->len + sizeof(*hdr);
		buf = bt_buf_get_rx(BT_BUF_ACL_IN, K_FOREVER);
		break;
	}
	default:
		LOG_ERR("Unknown/Unhandled HCI type: %d", packet_type);
		break;
	}

	if (buf && (len <= net_buf_tailroom(buf))) {
		net_buf_add_mem(buf, resp_buf->data, len);
		hci->recv(dev, buf);
	}
}

static const struct bt_hci_driver_api drv = {
	.open = bt_siwg917_open,
	.send = bt_siwg917_send,
};

#define HCI_DEVICE_INIT(inst)                                                                      \
	static struct hci_data hci_data_##inst;                                                    \
	DEVICE_DT_INST_DEFINE(inst, NULL, NULL, &hci_data_##inst, NULL, POST_KERNEL,               \
			      CONFIG_KERNEL_INIT_PRIORITY_DEVICE, &drv)

/* Only one instance supported right now */
HCI_DEVICE_INIT(0)

/* IRQn 74 is used for communication with co-processor */
Z_ISR_DECLARE(74, ISR_FLAG_DIRECT, IRQ074_Handler, 0);
