/*
 * Copyright (c) 2023 Antmicro
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#define DT_DRV_COMPAT silabs_siwx917_wifi

#include <zephyr/net/offloaded_netdev.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/logging/log.h>

#include "sl_wifi_callback_framework.h"
#include "sl_wifi.h"
#include "sl_net.h"

LOG_MODULE_REGISTER(siwx917_wifi);

struct siwx917_dev {
	struct net_if *iface;
	enum wifi_iface_state state;
	scan_result_cb_t scan_res_cb;
};

static void siwx917_report_scan_res(struct siwx917_dev *sidev, sl_wifi_scan_result_t *result,
				    int item)
{
	static const struct {
		int sl_val;
		int z_val;
	} security_convert[] = {
		{ SL_WIFI_OPEN,            WIFI_SECURITY_TYPE_NONE    },
		{ SL_WIFI_WEP,             WIFI_SECURITY_TYPE_WEP     },
		{ SL_WIFI_WPA,             WIFI_SECURITY_TYPE_WPA_PSK },
		{ SL_WIFI_WPA2,            WIFI_SECURITY_TYPE_PSK     },
		{ SL_WIFI_WPA3,            WIFI_SECURITY_TYPE_SAE     },
		{ SL_WIFI_WPA3_TRANSITION, WIFI_SECURITY_TYPE_SAE     },
		{ SL_WIFI_WPA_ENTERPRISE,  WIFI_SECURITY_TYPE_EAP     },
		{ SL_WIFI_WPA2_ENTERPRISE, WIFI_SECURITY_TYPE_EAP     },
	};
	struct wifi_scan_result tmp = {
		.channel = result->scan_info[item].rf_channel,
		.rssi = result->scan_info[item].rssi_val,
		.ssid_length = strlen(result->scan_info[item].ssid),
		.mac_length = sizeof(result->scan_info[item].bssid),
		.security = WIFI_SECURITY_TYPE_UNKNOWN,
		.mfp = WIFI_MFP_UNKNOWN,
		/* FIXME: fill .mfp, .band and .channel */
	};
	int i;

	memcpy(tmp.ssid, result->scan_info[item].ssid, tmp.ssid_length);
	memcpy(tmp.mac, result->scan_info[item].bssid, tmp.mac_length);
	for (i = 0; i < ARRAY_SIZE(security_convert); i++) {
		if (security_convert[i].sl_val == result->scan_info[item].security_mode) {
			tmp.security = security_convert[i].z_val;
		}
	}
	sidev->scan_res_cb(sidev->iface, 0, &tmp);
}

static unsigned int siwx917_on_scan(sl_wifi_event_t event, sl_wifi_scan_result_t *result,
				    uint32_t result_size, void *arg)
{
	struct siwx917_dev *sidev = arg;
	int i;

	if (!sidev->scan_res_cb) {
		return -EFAULT;
	}
	for (i = 0; i < result->scan_count; i++) {
		siwx917_report_scan_res(sidev, result, i);
	}
	sidev->scan_res_cb(sidev->iface, 0, NULL);
	sidev->state = WIFI_STATE_INACTIVE;
	return 0;
}

static int siwx917_scan(const struct device *dev, struct wifi_scan_params *z_scan_config,
			scan_result_cb_t cb)
{
	sl_wifi_scan_configuration_t sl_scan_config = { };
	struct siwx917_dev *sidev = dev->data;
	int ret;

	if (sidev->state != WIFI_STATE_INACTIVE) {
		return -EBUSY;
	}

	/* FIXME: fill sl_scan_config with values from z_scan_config */
	sl_scan_config.type = SL_WIFI_SCAN_TYPE_ACTIVE;
	sl_scan_config.channel_bitmap_2g4 = 0xFFFF;
	memset(sl_scan_config.channel_bitmap_5g, 0xFF, sizeof(sl_scan_config.channel_bitmap_5g));

	sidev->scan_res_cb = cb;
	ret = sl_wifi_start_scan(SL_WIFI_CLIENT_INTERFACE, NULL, &sl_scan_config);
	if (ret != SL_STATUS_IN_PROGRESS) {
		return -EIO;
	}
	sidev->state = WIFI_STATE_SCANNING;

	return 0;
}

static int siwx917_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct siwx917_dev *sidev = dev->data;

	memset(status, 0, sizeof(*status));
	status->state = sidev->state;
	return 0;
}

static struct net_offload siwx917_offload = {
};

static void siwx917_iface_init(struct net_if *iface)
{
	struct siwx917_dev *sidev = iface->if_dev->dev->data;
	sl_mac_address_t mac_addr;
	sl_status_t status;

	iface->if_dev->offload = &siwx917_offload;
	sidev->state = WIFI_STATE_INTERFACE_DISABLED;
	sidev->iface = iface;

	sl_wifi_set_scan_callback(siwx917_on_scan, sidev);
	sl_wifi_get_mac_address(SL_WIFI_CLIENT_INTERFACE, &mac_addr);
	net_if_set_link_addr(iface, mac_addr.octet, sizeof(mac_addr.octet), NET_LINK_ETHERNET);

	status = sl_net_init(SL_NET_WIFI_CLIENT_INTERFACE, NULL, NULL, NULL);
	if (status) {
		LOG_ERR("sl_net_init(): %#04x", status);
		return;
	}
	sidev->state = WIFI_STATE_INACTIVE;
}

static int siwx917_dev_init(const struct device *dev)
{
	return 0;
}

static enum offloaded_net_if_types siwx917_get_type(void)
{
	return L2_OFFLOADED_NET_IF_TYPE_WIFI;
}

static const struct wifi_mgmt_ops siwx917_mgmt = {
	.scan         = siwx917_scan,
	.iface_status = siwx917_status,
};

static const struct net_wifi_mgmt_offload siwx917_api = {
	.wifi_iface.iface_api.init = siwx917_iface_init,
	.wifi_iface.get_type = siwx917_get_type,
	.wifi_mgmt_api = &siwx917_mgmt,
};

static struct siwx917_dev siwx917_dev;
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, siwx917_dev_init, NULL, &siwx917_dev, NULL,
				  CONFIG_WIFI_INIT_PRIORITY, &siwx917_api, NET_ETH_MTU);

/* IRQn 74 is used for communication with co-processor */
Z_ISR_DECLARE(74, ISR_FLAG_DIRECT, IRQ074_Handler, 0);
