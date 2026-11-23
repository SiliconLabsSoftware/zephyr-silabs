# Copyright (c) 2026 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

zephyr_library()
zephyr_library_sources(
  sl_token_manager_lock_zephyr.c
  sl_zigbee_token_zephyr_shim.c
  sl_token_manager_zephyr_runtime.c
)
