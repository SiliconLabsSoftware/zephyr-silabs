# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Silicon Laboratories Inc.

if(CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_PROVIDER_SILABS)
zephyr_library_named(secure_storage_silabs)
zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)
zephyr_library_sources(secure_storage_aead_get.c)
zephyr_library_include_directories($<TARGET_PROPERTY:tfpsacrypto,INCLUDE_DIRECTORIES>)
endif()
