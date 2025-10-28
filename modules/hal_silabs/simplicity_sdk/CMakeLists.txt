# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(SECURITY_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/security)
set(LIBCRYPTOSOC_DIR ${ZEPHYR_HAL_SILABS_EXTRA_MODULE_DIR}/simplicity_sdk/util/third_party/crypto_ip/libcryptosoc)
set(MBEDTLS_DIR ${ZEPHYR_MBEDTLS_MODULE_DIR})

# Get SoC series number, i.e. translate efr32bg22 -> 22, mgm240p -> 24, simg301 -> 301
if(CONFIG_SOC_SERIES MATCHES "^ef[rm]32")
  string(SUBSTRING ${CONFIG_SOC_SERIES} 7 2 SILABS_DEVICE_FAMILY_NUMBER)
elseif(CONFIG_SOC_SERIES MATCHES "^si")
  string(SUBSTRING ${CONFIG_SOC_SERIES} 4 3 SILABS_DEVICE_FAMILY_NUMBER)
elseif(CONFIG_SOC_SERIES MATCHES "^.gm")
  string(SUBSTRING ${CONFIG_SOC_SERIES} 3 2 SILABS_DEVICE_FAMILY_NUMBER)
else()
  message(FATAL_ERROR "unknown part")
endif()

zephyr_include_directories(
  inc
)

zephyr_compile_definitions_ifdef(CONFIG_SILABS_SISDK_SE
  SL_SE_MANAGER_THREADING
)

set(vse_device_families 22 27)
if(CONFIG_SOC_FAMILY_SILABS_S2 AND NOT (SILABS_DEVICE_FAMILY_NUMBER IN_LIST vse_device_families))
  zephyr_compile_definitions_ifdef(CONFIG_SILABS_SISDK_SE
    SL_SE_MANAGER_YIELD_WHILE_WAITING_FOR_COMMAND_COMPLETION
  )
endif()

# PSA Crypto
if(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE OR CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE OR CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X)

zephyr_library_named(hal_silabs_crypto)

target_include_directories(hal_silabs_crypto PRIVATE
  ${MBEDTLS_DIR}/library
)

zephyr_include_directories(
  ${SECURITY_DIR}/sl_component/sl_psa_driver/inc
  ${SECURITY_DIR}/sl_component/sl_mbedtls_support/config
  ${SECURITY_DIR}/sl_component/sl_mbedtls_support/inc
)
zephyr_compile_definitions(
  MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE="sl_psa_crypto_config_zephyr.h"
)
zephyr_library_sources(
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_psa_driver_common.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_psa_driver_ghash.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_psa_driver_init.c
#  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_psa_trng.c
)
zephyr_library_link_libraries(mbedTLSBase)

# HSE
zephyr_library_sources_ifdef(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE
  ${SECURITY_DIR}/sl_component/se_manager/src/sl_se_manager_cipher.c
  ${SECURITY_DIR}/sl_component/se_manager/src/sl_se_manager_hash.c
  ${SECURITY_DIR}/sl_component/se_manager/src/sl_se_manager_key_derivation.c
  ${SECURITY_DIR}/sl_component/se_manager/src/sl_se_manager_key_handling.c
  ${SECURITY_DIR}/sl_component/se_manager/src/sl_se_manager_signature.c
  ${SECURITY_DIR}/sl_component/se_manager/src/sl_se_manager_attestation.c

  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_aead.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_builtin_keys.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_cipher.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_key_derivation.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_key_management.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_mac.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_driver_signature.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_opaque_driver_aead.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_opaque_driver_cipher.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_opaque_driver_mac.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_opaque_key_derivation.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_transparent_driver_aead.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_transparent_driver_cipher.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_transparent_driver_hash.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_transparent_driver_mac.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_transparent_key_derivation.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_se_version_dependencies.c
)

# VSE
zephyr_include_directories_ifdef(CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE
  ${LIBCRYPTOSOC_DIR}/include
  ${LIBCRYPTOSOC_DIR}/src
)
zephyr_library_sources_ifdef(CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/cryptoacc_management.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_driver_key_derivation.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_driver_trng.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_opaque_driver_builtin_keys.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_opaque_driver_mac.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_aead.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_cipher.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_hash.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_key_derivation.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_key_management.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_mac.c
  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_signature.c

  ${LIBCRYPTOSOC_DIR}/src/ba414ep_config.c
  ${LIBCRYPTOSOC_DIR}/src/ba431_config.c
  ${LIBCRYPTOSOC_DIR}/src/cryptodma_internal.c
  ${LIBCRYPTOSOC_DIR}/src/cryptolib_types.c
  ${LIBCRYPTOSOC_DIR}/src/sx_aes.c
  ${LIBCRYPTOSOC_DIR}/src/sx_blk_cipher.c
  ${LIBCRYPTOSOC_DIR}/src/sx_blk_cipher.h
  ${LIBCRYPTOSOC_DIR}/src/sx_dh_alg.c
  ${LIBCRYPTOSOC_DIR}/src/sx_ecc_curves.c
  ${LIBCRYPTOSOC_DIR}/src/sx_ecc_keygen_alg.c
  ${LIBCRYPTOSOC_DIR}/src/sx_ecdsa_alg.c
  ${LIBCRYPTOSOC_DIR}/src/sx_hash.c
  ${LIBCRYPTOSOC_DIR}/src/sx_math.c
  ${LIBCRYPTOSOC_DIR}/src/sx_memcmp.c
  ${LIBCRYPTOSOC_DIR}/src/sx_memcpy.c
  ${LIBCRYPTOSOC_DIR}/src/sx_primitives.c
  ${LIBCRYPTOSOC_DIR}/src/sx_rng.c
  ${LIBCRYPTOSOC_DIR}/src/sx_trng.c
)

endif() # PSA Crypto
