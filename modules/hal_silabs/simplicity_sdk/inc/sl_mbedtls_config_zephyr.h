/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SL_MBEDTLS_CONFIG_ZEPHYR_H
#define SL_MBEDTLS_CONFIG_ZEPHYR_H

#include "sli_mbedtls_omnipresent.h"

/* Legacy mbed TLS ALT APIs are not accelerated in Zephyr
 * #include "sli_mbedtls_acceleration.h"
 */

/* From sl_mbedtls_device_config.h */
#define SL_SE_SUPPORT_FW_PRIOR_TO_1_2_2              0
#define SL_SE_ASSUME_FW_AT_LEAST_1_2_2               1
#define SL_SE_ASSUME_FW_UNAFFECTED_BY_ED25519_ERRATA 0

#endif
