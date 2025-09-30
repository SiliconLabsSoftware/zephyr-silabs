# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Silicon Laboratories Inc.

zephyr_library_sources_ifdef(CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_SILABS
  secure_storage_aead_get.c
)
