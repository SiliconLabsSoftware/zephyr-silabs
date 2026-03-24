/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SL_PSA_CRYPTO_CONFIG_ZEPHYR_H
#define SL_PSA_CRYPTO_CONFIG_ZEPHYR_H

#include "sli_mbedtls_omnipresent.h"

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE)
#define PSA_CRYPTO_DRIVER_SILABS_HSE
#endif

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE)
#define PSA_CRYPTO_DRIVER_SILABS_VSE
#endif

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X)
#define PSA_CRYPTO_DRIVER_SILABS_SI91X
#endif

/* From sl_mbedtls_device_config.h */
#define SL_SE_SUPPORT_FW_PRIOR_TO_1_2_2              0
#define SL_SE_ASSUME_FW_AT_LEAST_1_2_2               1
#define SL_SE_ASSUME_FW_UNAFFECTED_BY_ED25519_ERRATA 0

/* Should be exposed as Kconfig in the future */
#define SL_SE_BUILTIN_KEY_AES128_ALG_CONFIG         (PSA_ALG_CTR)
#define SL_CRYPTOACC_BUILTIN_KEY_PUF_ALG            (PSA_ALG_PBKDF2_AES_CMAC_PRF_128)
#define SL_VSE_BUFFER_TRNG_DATA_DURING_SLEEP        (0)
#define SL_VSE_MAX_TRNG_WORDS_BUFFERED_DURING_SLEEP (63)

#include "sli_psa_acceleration.h"
/* Convert definitions to be compatible with TF-PSA-Crypto 1.1 */
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE

#endif
