/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 *
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
