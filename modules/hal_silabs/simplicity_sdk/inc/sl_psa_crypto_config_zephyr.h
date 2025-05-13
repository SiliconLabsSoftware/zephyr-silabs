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

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X)
#define PSA_CRYPTO_DRIVER_SILABS_SI91X
#endif

/* Should be exposed as Kconfig in the future */
#define SL_SE_BUILTIN_KEY_AES128_ALG_CONFIG         (PSA_ALG_CTR)
#define SL_CRYPTOACC_BUILTIN_KEY_PUF_ALG            (PSA_ALG_PBKDF2_AES_CMAC_PRF_128)
#define SL_VSE_BUFFER_TRNG_DATA_DURING_SLEEP        (0)
#define SL_VSE_MAX_TRNG_WORDS_BUFFERED_DURING_SLEEP (63)

#include "sli_psa_acceleration.h"

#if defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X)
/*
 * SiWx91x does not support acceleration for the multipart hash API.
 * Perform the same config translation as config_adjust_legacy_from_psa.h does
 * when no acceleration is available at all.
 */

#ifdef CONFIG_PSA_WANT_ALG_MD5
#ifndef MBEDTLS_PSA_BUILTIN_ALG_MD5
#define MBEDTLS_PSA_BUILTIN_ALG_MD5 1
#endif
#ifndef MBEDTLS_MD5_C
#define MBEDTLS_MD5_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_RIPEMD160
#ifndef MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160
#define MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160 1
#endif
#ifndef MBEDTLS_RIPEMD160_C
#define MBEDTLS_RIPEMD160_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA_1
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA_1
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_1 1
#endif
#ifndef MBEDTLS_SHA1_C
#define MBEDTLS_SHA1_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA_224
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA_224
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_224 1
#endif
#ifndef MBEDTLS_SHA224_C
#define MBEDTLS_SHA224_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA_256
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA_256
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_256 1
#endif
#ifndef MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA_512
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA_512
#define MBEDTLS_PSA_BUILTIN_ALG_SHA_512 1
#endif
#ifndef MBEDTLS_SHA512_C
#define MBEDTLS_SHA512_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA3_224
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA3_224
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_224 1
#endif
#ifndef MBEDTLS_SHA3_C
#define MBEDTLS_SHA3_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA3_256
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA3_256
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_256 1
#endif
#ifndef MBEDTLS_SHA3_C
#define MBEDTLS_SHA3_C
#endif
#endif

#ifdef CONFIG_PSA_WANT_ALG_SHA3_512
#ifndef MBEDTLS_PSA_BUILTIN_ALG_SHA3_512
#define MBEDTLS_PSA_BUILTIN_ALG_SHA3_512 1
#endif
#ifndef MBEDTLS_SHA3_C
#define MBEDTLS_SHA3_C
#endif
#endif

#endif /* defined(CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X) */

#endif
