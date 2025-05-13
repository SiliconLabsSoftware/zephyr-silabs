# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(SISDK_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk)
set(WISECONNECT_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect)

if(CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X)

zephyr_library_named(hal_silabs_siwx91x_crypto)
zephyr_library_link_libraries(mbedTLSBase)

zephyr_include_directories(
  config
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/aes/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/attestation/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ccm/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/chachapoly/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/crypto_utility/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ecdh/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/gcm/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/hmac/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/mac/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/multithread/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/puf/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/sha/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/trng/inc
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/wrap/inc
)

zephyr_compile_definitions(
  SLI_CIPHER_DEVICE_SI91X
  SLI_TRNG_DEVICE_SI91X
  SLI_ECDH_DEVICE_SI91X
  SLI_MAC_DEVICE_SI91X
  SLI_SHA_DEVICE_SI91X
  SLI_MULTITHREAD_DEVICE_SI91X
  SLI_PUF_ENABLE
  SLI_SECURE_KEY_STORAGE_DEVICE_SI91X
  PSA_HAVE_SOFT_KEY_TYPE_AES # Causes MBEDTLS_PSA_BUILTIN_CIPHER to be set
  MBEDTLS_PSA_ECC_ACCEL_INCOMPLETE_KEY_TYPES # Accelerated ECC support can't import keys
)

zephyr_library_sources(
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/src/sli_si91x_crypto_driver_functions.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/aes/src/sl_si91x_aes.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/aes/src/sl_si91x_psa_aes.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/attestation/src/sl_si91x_attestation.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ccm/src/sl_si91x_ccm.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/chachapoly/src/sl_si91x_chachapoly.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/crypto_utility/src/sl_si91x_crypto_utility.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ecdh/src/sl_si91x_ecdh.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ecdh/src/sl_si91x_psa_ecdh.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/gcm/src/sl_si91x_gcm.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/hmac/src/sl_si91x_hmac.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/mac/src/sl_si91x_psa_mac.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/multithread/src/sl_si91x_crypto_thread.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/puf/src/sl_si91x_puf.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/sha/src/sl_si91x_psa_sha.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/sha/src/sl_si91x_sha.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/trng/src/sl_si91x_psa_trng.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/trng/src/sl_si91x_trng.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/wrap/src/sl_si91x_psa_wrap.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/wrap/src/sl_si91x_wrap.c
)

if(CONFIG_PSA_WANT_ALG_ECDSA)
zephyr_include_directories(
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ecdsa/inc
)
zephyr_compile_definitions(
  SLI_ECDSA_DEVICE_SI91X
)
zephyr_library_sources(
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ecdsa/src/sl_si91x_ecdsa.c
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/ecdsa/src/sl_si91x_psa_ecdsa.c
)
endif()

if(CONFIG_PSA_WANT_ALG_CCM OR CONFIG_PSA_WANT_ALG_GCM OR CONFIG_PSA_WANT_ALG_CHACHA20_POLY1305)
zephyr_include_directories(
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/aead/inc
)
zephyr_compile_definitions(
  SLI_AEAD_DEVICE_SI91X
)
zephyr_library_sources(
  ${WISECONNECT_DIR}/components/device/silabs/si91x/wireless/crypto/aead/src/sl_si91x_psa_aead.c
)
endif()

endif()
