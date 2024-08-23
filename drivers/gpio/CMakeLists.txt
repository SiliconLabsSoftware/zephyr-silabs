# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

zephyr_library_sources_ifdef(CONFIG_GPIO_SILABS_SIWX917 gpio_silabs_siwx917.c)
zephyr_library_sources_ifdef(CONFIG_GPIO_SILABS_SIWX917_UULP gpio_silabs_siwx917_uulp.c)
