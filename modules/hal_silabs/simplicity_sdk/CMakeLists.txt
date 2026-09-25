# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(SECURITY_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/security)
set(LIBCRYPTOSOC_DIR ${ZEPHYR_HAL_SILABS_EXTRA_MODULE_DIR}/simplicity_sdk/util/third_party/crypto_ip/libcryptosoc)

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

# PSA Crypto
if(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE OR CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE OR CONFIG_PSA_CRYPTO_DRIVER_SILABS_SIWX91X)

zephyr_library_named(hal_silabs_crypto)

# VSE
zephyr_include_directories_ifdef(CONFIG_PSA_CRYPTO_DRIVER_SILABS_VSE
  ${LIBCRYPTOSOC_DIR}/include
  ${LIBCRYPTOSOC_DIR}/src
  ${LIBCRYPTOSOC_DIR}/src/platform/silicon_labs
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
  ${LIBCRYPTOSOC_DIR}/src/platform/silicon_labs/sli_libcryptosoc.c
)

endif() # PSA Crypto
