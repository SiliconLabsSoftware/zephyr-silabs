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

LOG_MODULE_REGISTER(siwx917_wifi);

struct siwx917_dev {
	enum wifi_iface_state state;
};

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
	iface->if_dev->offload = &siwx917_offload;
	sidev->state = WIFI_STATE_INTERFACE_DISABLED;
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
