/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SL_PSA_CRYPTO_CONFIG_ZEPHYR_H
#define SL_PSA_CRYPTO_CONFIG_ZEPHYR_H

#include <zephyr/devicetree.h>

#include <em_device.h>

/*
 * Configure accelerators according to hardware capabilities.
 * This configuration must align with sli_mbedtls_omnipresent.h
 * from the HAL.
 */
#if defined(CONFIG_SOC_FAMILY_SILABS_SIWX91X)
#define SLI_MBEDTLS_DEVICE_SI91X            1
#define SLI_CIPHER_DEVICE_SI91X             1
#define SLI_TRNG_DEVICE_SI91X               1
#define SLI_ECDH_DEVICE_SI91X               1
#define SLI_MAC_DEVICE_SI91X                1
#define SLI_SHA_DEVICE_SI91X                1
#define SLI_MULTITHREAD_DEVICE_SI91X        1
#define SLI_SECURE_KEY_STORAGE_DEVICE_SI91X 1
#define SL_SI91X_SIDE_BAND_CRYPTO           1
#define SLI_AEAD_DEVICE_SI91X               1
/* Disable hardware acceleration for ECDSA due to NWP bug in message signing */
/* #define SLI_ECDSA_DEVICE_SI91X           1 */

#endif /* CONFIG_SOC_FAMILY_SILABS_SIWX91X */

#include "sli_psa_acceleration.h"

#endif
