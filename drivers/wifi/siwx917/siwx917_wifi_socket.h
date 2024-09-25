/*
 * Copyright (c) 2023 Antmicro
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SIWX917_WIFI_SOCKET_H
#define SIWX917_WIFI_SOCKET_H

#include <zephyr/net/net_if.h>
#include <zephyr/net/offloaded_netdev.h>

struct siwx917_dev;

enum offloaded_net_if_types siwx917_get_type(void);
void siwx917_on_join_ipv4(struct siwx917_dev *sidev);
void siwx917_on_join_ipv6(struct siwx917_dev *sidev);
void siwx917_sock_init(struct net_if *iface)

#endif
