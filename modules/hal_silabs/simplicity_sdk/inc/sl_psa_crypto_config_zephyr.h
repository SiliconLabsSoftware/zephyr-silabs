/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SL_PSA_CRYPTO_CONFIG_ZEPHYR_H
#define SL_PSA_CRYPTO_CONFIG_ZEPHYR_H

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE)
#define PSA_CRYPTO_DRIVER_SILABS_HSE
#endif

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE)
#define PSA_CRYPTO_DRIVER_SILABS_VSE
#endif

/* Should be exposed as Kconfig in the future */
#define SL_SE_BUILTIN_KEY_AES128_ALG_CONFIG         (PSA_ALG_CTR)
#define SL_CRYPTOACC_BUILTIN_KEY_PUF_ALG            (PSA_ALG_PBKDF2_AES_CMAC_PRF_128)
#define SL_VSE_BUFFER_TRNG_DATA_DURING_SLEEP        (0)
#define SL_VSE_MAX_TRNG_WORDS_BUFFERED_DURING_SLEEP (63)

#include "sli_psa_acceleration.h"

#endif
