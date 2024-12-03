/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SIWX917_WIFI_H
#define SIWX917_WIFI_H

#include <zephyr/net/net_context.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/wifi.h>
#include <zephyr/kernel.h>

#include "sl_ieee802_types.h"
#include "sl_si91x_socket_types.h"
#include "sl_si91x_protocol_types.h"

struct siwx917_dev {
	struct net_if *iface;
	sl_mac_address_t macaddr;
	enum wifi_iface_state state;
	scan_result_cb_t scan_res_cb;

#ifdef CONFIG_WIFI_SIWX917_NET_STACK_OFFLOAD
	struct k_event fds_recv_event;
	sl_si91x_fd_set fds_watch;
	struct {
		net_context_recv_cb_t cb;
		void *user_data;
		struct net_context *context;
	} fds_cb[NUMBER_OF_SOCKETS];
#endif
};

#endif
