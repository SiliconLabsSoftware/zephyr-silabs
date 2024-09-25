# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Silicon Laboratories Inc.

zephyr_library_sources_ifdef(CONFIG_WIFI_SIWX917 siwx917_wifi.c siwx917_wifi_socket.c)
