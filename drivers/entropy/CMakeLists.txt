# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

zephyr_library_amend()
zephyr_library_sources_ifdef(CONFIG_ENTROPY_SILABS_CRYPTOACC_TRNG entropy_silabs_cryptoacc_trng.c)
zephyr_library_link_libraries_ifdef(CONFIG_ENTROPY_SILABS_CRYPTOACC_TRNG mbedTLS)
