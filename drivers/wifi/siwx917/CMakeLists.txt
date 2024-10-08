# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Silicon Laboratories Inc.

if(CONFIG_WIFI_SIWX917)

zephyr_library_sources(siwx917_wifi.c)
zephyr_library_sources_ifdef(CONFIG_WIFI_SIWX917_NET_STACK_OFFLOAD siwx917_wifi_socket.c)

endif()
