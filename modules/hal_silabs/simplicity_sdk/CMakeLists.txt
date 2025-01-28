# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(SECURITY_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/security)

# Get SoC series number, i.e. translate e.g. efr32bg22 -> 22
string(SUBSTRING ${CONFIG_SOC_SERIES} 7 2 SILABS_DEVICE_FAMILY_NUMBER)

zephyr_include_directories(
  inc
)

zephyr_compile_definitions_ifdef(CONFIG_SOC_GECKO_SE
  SL_SE_MANAGER_THREADING
)

set(vse_device_families 22 27)
if(NOT (SILABS_DEVICE_FAMILY_NUMBER IN_LIST vse_device_families))
  zephyr_compile_definitions_ifdef(CONFIG_SOC_GECKO_SE
    SL_SE_MANAGER_YIELD_WHILE_WAITING_FOR_COMMAND_COMPLETION
  )
endif()

# PSA Crypto
if(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE OR CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE)

zephyr_library_named(hal_silabs_crypto)

zephyr_include_directories(
  ${SECURITY_DIR}/sl_component/sl_psa_driver/inc
  ${SECURITY_DIR}/sl_component/sl_mbedtls_support/config
  ${SECURITY_DIR}/sl_component/sl_mbedtls_support/inc
)
zephyr_compile_definitions(
  MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE="sl_psa_crypto_config_zephyr.h"
)
zephyr_library_sources(
#  ${SECURITY_DIR}/sl_component/sl_psa_driver/src/sli_psa_driver_common.c
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
# TODO

endif() # PSA Crypto
