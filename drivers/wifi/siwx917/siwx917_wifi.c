/*
 * Copyright (c) 2023 Antmicro
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#define DT_DRV_COMPAT silabs_siwx917_wifi

#include <zephyr/logging/log.h>

#include "siwx917_wifi.h"
#include "siwx917_wifi_socket.h"

#include "sl_net_constants.h"
#include "sl_wifi_types.h"
#include "sl_wifi_callback_framework.h"
#include "sl_wifi.h"
#include "sl_net.h"

LOG_MODULE_REGISTER(siwx917_wifi);

static unsigned int siwx917_on_join(sl_wifi_event_t event,
				    char *result, uint32_t result_size, void *arg)
{
	struct siwx917_dev *sidev = arg;

	if (*result != 'C') {
		/* TODO: report the real reason of failure */
		wifi_mgmt_raise_connect_result_event(sidev->iface, WIFI_STATUS_CONN_FAIL);
		sidev->state = WIFI_STATE_INACTIVE;
		return 0;
	}

	wifi_mgmt_raise_connect_result_event(sidev->iface, WIFI_STATUS_CONN_SUCCESS);
	sidev->state = WIFI_STATE_COMPLETED;

	siwx917_on_join_ipv4(sidev);
	siwx917_on_join_ipv6(sidev);

	return 0;
}

static int siwx917_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	sl_wifi_client_configuration_t wifi_config = {
		.bss_type = SL_WIFI_BSS_TYPE_INFRASTRUCTURE,
	};
	int ret;

	switch (params->security) {
	case WIFI_SECURITY_TYPE_NONE:
		wifi_config.security = SL_WIFI_OPEN;
		wifi_config.encryption = SL_WIFI_NO_ENCRYPTION;
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		wifi_config.security = SL_WIFI_WPA;
		wifi_config.encryption = SL_WIFI_DEFAULT_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_PSK:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_TKIP_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_PSK_SHA256:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_CCMP_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_SAE:
		/* TODO: Support the case where MFP is not required */
		wifi_config.security = SL_WIFI_WPA3;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_DEFAULT_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	/* Zephyr WiFi shell doesn't specify how to pass credential for these
	 * key managements.
	 */
	case WIFI_SECURITY_TYPE_WEP: /* SL_WIFI_WEP/SL_WIFI_WEP_ENCRYPTION */
	case WIFI_SECURITY_TYPE_EAP: /* SL_WIFI_WPA2_ENTERPRISE/<various> */
	case WIFI_SECURITY_TYPE_WAPI:
	default:
		return -ENOTSUP;
	}

	if (params->band != WIFI_FREQ_BAND_UNKNOWN && params->band != WIFI_FREQ_BAND_2_4_GHZ) {
		return -ENOTSUP;
	}

	if (params->psk_length) {
		sl_net_set_credential(SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID, SL_NET_WIFI_PSK,
				      params->psk, params->psk_length);
	}

	if (params->sae_password_length) {
		sl_net_set_credential(SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID, SL_NET_WIFI_PSK,
				      params->sae_password, params->sae_password_length);
	}

	if (params->channel != WIFI_CHANNEL_ANY) {
		wifi_config.channel.channel = params->channel;
	}

	wifi_config.ssid.length = params->ssid_length,
	memcpy(wifi_config.ssid.value, params->ssid, params->ssid_length);

	ret = sl_wifi_connect(SL_WIFI_CLIENT_INTERFACE, &wifi_config, 0);
	if (ret != SL_STATUS_IN_PROGRESS) {
		return -EIO;
	}

	return 0;
}

static int siwx917_disconnect(const struct device *dev)
{
	struct siwx917_dev *sidev = dev->data;
	int ret;

	ret = sl_wifi_disconnect(SL_WIFI_CLIENT_INTERFACE);
	if (ret) {
		return -EIO;
	}
	sidev->state = WIFI_STATE_INACTIVE;
	return 0;
}

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
	int32_t rssi = -1;

	memset(status, 0, sizeof(*status));
	status->state = sidev->state;
	sl_wifi_get_signal_strength(SL_WIFI_CLIENT_INTERFACE, &rssi);
	status->rssi = rssi;
	return 0;
}

static void siwx917_iface_init(struct net_if *iface)
{
	struct siwx917_dev *sidev = iface->if_dev->dev->data;
	sl_status_t status;

	sidev->state = WIFI_STATE_INTERFACE_DISABLED;
	sidev->iface = iface;

	siwx917_sock_init(iface);
	sl_wifi_set_scan_callback(siwx917_on_scan, sidev);
	sl_wifi_set_join_callback(siwx917_on_join, sidev);

	status = sl_wifi_get_mac_address(SL_WIFI_CLIENT_INTERFACE, &sidev->macaddr);
	if (status) {
		LOG_ERR("sl_wifi_get_mac_address(): %#04x", status);
		return;
	}
	net_if_set_link_addr(iface, sidev->macaddr.octet, sizeof(sidev->macaddr.octet),
			     NET_LINK_ETHERNET);

	sidev->state = WIFI_STATE_INACTIVE;
}

static int siwx917_dev_init(const struct device *dev)
{
	return 0;
}

static const struct wifi_mgmt_ops siwx917_mgmt = {
	.scan         = siwx917_scan,
	.connect      = siwx917_connect,
	.disconnect   = siwx917_disconnect,
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
