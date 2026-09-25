# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(sisdk_dir ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk)
set(wiseconnect_dir ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect)

if(CONFIG_SILABS_WISECONNECT_PSA_CRYPTO)
  zephyr_library_compile_definitions(
    SL_SI91X_SIDE_BAND_CRYPTO=1
  )

  zephyr_library_named(wiseconnect_crypto)
  zephyr_library_link_libraries(tfpsacrypto)

  # Crypto drivers need access to internal TF-PSA-Crypto headers
  zephyr_library_include_directories($<TARGET_PROPERTY:tfpsacrypto,INCLUDE_DIRECTORIES>)

  # Add crypto config as preinclude to ensure feature enable macros are available to driver implementations
  zephyr_library_compile_options("SHELL:$<TARGET_PROPERTY:compiler,include_file> sl_psa_crypto_config_zephyr.h")
  zephyr_library_compile_options(-Wno-unused-function)

  zephyr_include_directories(
    config
    ${sisdk_dir}/platform/security/sl_component/sl_mbedtls_support/config
    ${sisdk_dir}/platform/security/sl_component/sl_mbedtls_support/inc
    ${sisdk_dir}/platform/security/sl_component/sl_psa_driver/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/aead/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/aes/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/attestation/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ccm/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/chachapoly/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/crypto_utility/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ecdh/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/gcm/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/hmac/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/mac/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/multithread/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/sha/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/trng/inc
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/wrap/inc
  )

  zephyr_library_sources(
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/src/sli_si91x_crypto_driver_functions.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/aead/src/sl_si91x_psa_aead.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/aes/src/sl_si91x_aes.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/aes/src/sl_si91x_mp_aes.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/aes/src/sl_si91x_psa_aes.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/attestation/src/sl_si91x_attestation.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ccm/src/sl_si91x_ccm.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ccm/src/sl_si91x_mp_ccm.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/chachapoly/src/sl_si91x_chachapoly.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/crypto_utility/src/sl_si91x_crypto_utility.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ecdh/src/sl_si91x_ecdh.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ecdh/src/sl_si91x_psa_ecdh.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/gcm/src/sl_si91x_gcm.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/hmac/src/sl_si91x_hmac.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/mac/src/sl_si91x_psa_mac.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/multithread/src/sl_si91x_crypto_thread.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/sha/src/sl_si91x_psa_sha.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/sha/src/sl_si91x_sha.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/trng/src/sl_si91x_psa_trng.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/trng/src/sl_si91x_trng.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/wrap/src/sl_si91x_psa_wrap.c
    ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/wrap/src/sl_si91x_wrap.c
  )

  if(CONFIG_PSA_WANT_ALG_ECDSA)
  # Temporarily disable hardware acceleration for ECDSA due to NWP bug in message signing
  # zephyr_include_directories(
  #   ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ecdsa/inc
  # )
  # zephyr_library_sources(
  #   ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ecdsa/src/sl_si91x_ecdsa.c
  #   ${wiseconnect_dir}/components/device/silabs/si91x/wireless/crypto/ecdsa/src/sl_si91x_psa_ecdsa.c
  # )
  endif()
endif()
