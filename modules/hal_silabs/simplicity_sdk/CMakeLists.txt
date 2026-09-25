# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(security_dir ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/security)
set(libcryptosoc_dir ${ZEPHYR_HAL_SILABS_EXTRA_MODULE_DIR}/simplicity_sdk/util/third_party/crypto_ip/libcryptosoc)

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

# PSA Crypto for VSE
if(CONFIG_SILABS_SISDK_PSA_CRYPTO AND CONFIG_DT_HAS_SILABS_GECKO_TRNG_ENABLED)
  zephyr_library_named(hal_silabs_crypto)

  zephyr_library_compile_definitions(SL_SE_MANAGER_THREADING=1)
  zephyr_library_link_libraries(tfpsacrypto)
  # Crypto drivers need access to internal TF-PSA-Crypto headers
  zephyr_library_include_directories($<TARGET_PROPERTY:tfpsacrypto,INCLUDE_DIRECTORIES>)

  zephyr_include_directories(
    ${libcryptosoc_dir}/include
    ${libcryptosoc_dir}/src
    ${libcryptosoc_dir}/src/platform/silicon_labs
  )

  zephyr_library_sources(
    ${security_dir}/sl_component/sl_psa_driver/src/cryptoacc_management.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_driver_key_derivation.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_driver_trng.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_opaque_driver_builtin_keys.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_opaque_driver_mac.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_aead.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_cipher.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_hash.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_key_derivation.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_key_management.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_mac.c
    ${security_dir}/sl_component/sl_psa_driver/src/sli_cryptoacc_transparent_driver_signature.c

    ${libcryptosoc_dir}/src/ba414ep_config.c
    ${libcryptosoc_dir}/src/ba431_config.c
    ${libcryptosoc_dir}/src/cryptodma_internal.c
    ${libcryptosoc_dir}/src/cryptolib_types.c
    ${libcryptosoc_dir}/src/sx_aes.c
    ${libcryptosoc_dir}/src/sx_blk_cipher.c
    ${libcryptosoc_dir}/src/sx_blk_cipher.h
    ${libcryptosoc_dir}/src/sx_dh_alg.c
    ${libcryptosoc_dir}/src/sx_ecc_curves.c
    ${libcryptosoc_dir}/src/sx_ecc_keygen_alg.c
    ${libcryptosoc_dir}/src/sx_ecdsa_alg.c
    ${libcryptosoc_dir}/src/sx_hash.c
    ${libcryptosoc_dir}/src/sx_math.c
    ${libcryptosoc_dir}/src/sx_memcmp.c
    ${libcryptosoc_dir}/src/sx_memcpy.c
    ${libcryptosoc_dir}/src/sx_primitives.c
    ${libcryptosoc_dir}/src/sx_rng.c
    ${libcryptosoc_dir}/src/sx_trng.c
    ${libcryptosoc_dir}/src/platform/silicon_labs/sli_libcryptosoc.c
  )
endif() # PSA Crypto
