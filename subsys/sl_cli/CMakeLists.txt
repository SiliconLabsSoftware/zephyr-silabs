# Copyright (c) 2026 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

zephyr_library()
zephyr_include_directories(.)
zephyr_library_sources(
  sl_cli_io_zephyr.c
  sl_cli_zephyr_runtime.c
)
