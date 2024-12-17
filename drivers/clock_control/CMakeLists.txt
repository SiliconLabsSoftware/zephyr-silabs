# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

zephyr_library_amend()
zephyr_library_sources_ifdef(CONFIG_CLOCK_CONTROL_SILABS_SIWX917 clock_control_silabs_siwx917.c)
