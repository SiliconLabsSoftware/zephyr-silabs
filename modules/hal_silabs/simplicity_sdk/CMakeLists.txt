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

# Zigbee stack (downstream-only prebuilt library integration)
set(BLOBS_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/zephyr/blobs/simplicity_sdk)
set(ZIGBEE_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/protocol/zigbee)
set(SERVICE_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/service)
set(LEGACY_HAL_DIR ${SERVICE_DIR}/legacy_hal)
set(TOKEN_MANAGER_DIR ${SERVICE_DIR}/token_manager)
set(SECURITY_MANAGER_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/plugin/security_manager)

function(add_prebuilt_library lib_name prebuilt_path)
  if(NOT CONFIG_BUILD_ONLY_NO_BLOBS)
    add_library(${lib_name} STATIC IMPORTED GLOBAL)
    set_target_properties(${lib_name} PROPERTIES
      IMPORTED_LOCATION ${BLOBS_DIR}/${prebuilt_path}
    )
    zephyr_link_libraries(${lib_name})
  endif()
endfunction()

function(add_zigbee_prebuilt_library lib_name component)
  add_prebuilt_library(${lib_name}
    zigbee/libs/build/gcc/cortex-m33/${component}/release/lib${component}.a
  )
endfunction()

if(CONFIG_ZIGBEE_SILABS)
  if(CONFIG_ZIGBEE_SILABS_STACK_LEAF)
    set(ZIGBEE_STACK_COMPONENT zigbee-pro-leaf-stack)
  elseif(CONFIG_ZIGBEE_SILABS_STACK_ROUTER)
    if(CONFIG_ZIGBEE_SILABS_RAIL_MUX)
      set(ZIGBEE_STACK_COMPONENT zigbee-pro-router-stack-rail-mux)
    else()
      set(ZIGBEE_STACK_COMPONENT zigbee-pro-router-stack)
    endif()
  else()
    if(CONFIG_ZIGBEE_SILABS_RAIL_MUX)
      set(ZIGBEE_STACK_COMPONENT zigbee-pro-stack-rail-mux)
    else()
      set(ZIGBEE_STACK_COMPONENT zigbee-pro-stack)
    endif()
  endif()

  add_zigbee_prebuilt_library(libzigbee_stack ${ZIGBEE_STACK_COMPONENT})

  if(CONFIG_ZIGBEE_SILABS_R23_SUPPORT)
    add_zigbee_prebuilt_library(libzigbee_r23 zigbee-r23-support)
  endif()

  if(CONFIG_ZIGBEE_SILABS_CBKE)
    add_zigbee_prebuilt_library(libzigbee_cbke_core zigbee-cbke-core)
    add_zigbee_prebuilt_library(libzigbee_cbke_dsa_sign zigbee-cbke-dsa-sign)
    add_zigbee_prebuilt_library(libzigbee_cbke_dsa_verify zigbee-cbke-dsa-verify)
    add_zigbee_prebuilt_library(libzigbee_cbke_163k1 zigbee-cbke-163k1)
    add_zigbee_prebuilt_library(libzigbee_cbke_283k1 zigbee-cbke-283k1)
    add_zigbee_prebuilt_library(libzigbee_cbke_dsa_verify_283k1 zigbee-cbke-dsa-verify-283k1)
  endif()

  if(CONFIG_ZIGBEE_SILABS_DEBUG_BASIC)
    add_zigbee_prebuilt_library(libzigbee_debug_basic zigbee-debug-basic)
  endif()

  if(CONFIG_ZIGBEE_SILABS_DEBUG_EXTENDED)
    add_zigbee_prebuilt_library(libzigbee_debug_extended zigbee-debug-extended)
  endif()

  if(CONFIG_ZIGBEE_SILABS_SOURCE_ROUTE)
    add_zigbee_prebuilt_library(libzigbee_source_route zigbee-source-route)
  endif()

  if(CONFIG_ZIGBEE_SILABS_GP)
    add_zigbee_prebuilt_library(libzigbee_gp zigbee-gp)
  endif()

  if(CONFIG_ZIGBEE_SILABS_ZLL)
    add_zigbee_prebuilt_library(libzigbee_zll zigbee-zll)
  endif()

  if(CONFIG_ZIGBEE_SILABS_DYNAMIC_COMMISSIONING)
    add_zigbee_prebuilt_library(libzigbee_dynamic_commissioning zigbee-dynamic-commissioning)
  endif()

  zephyr_compile_definitions(
    SL_ZIGBEE_CONFIG_HEADER="sl_zigbee_config.h"
    SL_COMPONENT_CATALOG_PRESENT
    PLATFORM_HEADER="platform-header.h"
    STACK_TYPES_HEADER=\"stack/include/sl_zigbee_types.h\"
    STACK_HEADER=\"stack/include/sl_zigbee.h\"
  )
  zephyr_include_directories(zigbee/config)

  zephyr_library_sources(
    zigbee/src/sl_zigbee_platform_shim.c
  )
  zephyr_library_sources_ifdef(CONFIG_SILABS_ZIGBEE_TOKEN_NVS
    zigbee/src/sl_zigbee_token_zephyr_shim.c
  )
  zephyr_library_sources_ifdef(CONFIG_SILABS_ZIGBEE_RUNTIME
    zigbee/src/sl_zigbee_hal_zephyr_shim.c
    zigbee/src/sl_zigbee_runtime_glue.c
    zigbee/src/sl_zigbee_stack_platform_glue.c
    zigbee/src/sl_zigbee_token_public_api_shim.c
    ${ZIGBEE_DIR}/platform/radio/rail_lib/plugin/sl_rail_util_ant_div/sl_rail_util_ant_div.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/aes-mmo-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/binding-table-baremetal-callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/binding-table-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/bootload_baremetal_callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/child_baremetal_callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/gp-types-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/gp-proxy-table-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/message_baremetal_callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/message_baremetal_wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/network-formation-baremetal-callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/network-formation-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/raw-message-baremetal-callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/raw-message-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/security_baremetal_callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/security_baremetal_wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/sl_zigbee_address_info_baremetal_wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/sl_zigbee_random_api_baremetal_wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/source-route-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/stack-info-baremetal-callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/stack-info-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/trust-center-baremetal-callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/trust-center-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/zigbee-device-stack-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/zigbee-security-manager-baremetal-wrapper.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/zll-api-baremetal-callbacks.c
    ${ZIGBEE_DIR}/stack/internal/src/baremetal/zll-api-baremetal-wrapper.c
  )
  zephyr_include_directories_ifdef(CONFIG_SILABS_ZIGBEE_RUNTIME
    ${ZIGBEE_DIR}/platform/radio/rail_lib/plugin/sl_rail_util_ant_div
  )
  # Force-include ant-div config only for the SDK plugin source (disabled defaults).
  if(CONFIG_SILABS_ZIGBEE_RUNTIME)
    set_source_files_properties(
      ${ZIGBEE_DIR}/platform/radio/rail_lib/plugin/sl_rail_util_ant_div/sl_rail_util_ant_div.c
      PROPERTIES COMPILE_OPTIONS
        "-include${CMAKE_CURRENT_LIST_DIR}/zigbee/config/sl_rail_util_ant_div_config.h"
    )
  endif()

  if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/zigbee/generated/components.cmake)
    include(zigbee/generated/components.cmake)
  endif()

  if(EXISTS ${ZIGBEE_DIR})
    set(BYTE_UTILITIES_DIR ${ZIGBEE_DIR}/util/plugin/byte_utilities)
    if(EXISTS ${BYTE_UTILITIES_DIR}/byte-utilities.h)
      zephyr_include_directories(${BYTE_UTILITIES_DIR})
      zephyr_library_sources(${BYTE_UTILITIES_DIR}/byte-utilities.c)
      zephyr_compile_definitions(SL_CATALOG_BYTE_UTILITIES_PRESENT)
    endif()

    if(EXISTS ${LEGACY_HAL_DIR}/inc/hal/hal.h)
      # zigbee/config provides led.h/button.h stubs so untouched SDK
      # hal.h includes resolve without porting those legacy HAL headers.
      # BEFORE keeps the stubs ahead of ${LEGACY_HAL_DIR}/inc.
      target_include_directories(zephyr_interface INTERFACE BEFORE
        ${CMAKE_CURRENT_LIST_DIR}/zigbee/config
      )
      zephyr_include_directories(
        ${LEGACY_HAL_DIR}/inc
        ${ZIGBEE_DIR}/util/silicon_labs/silabs_core/event_queue
      )
      zephyr_compile_definitions(
        CORTEXM3
        CORTEXM3_EFM32_MICRO
        CORTEXM3_EFR32
        PHY_RAIL
        SL_CODE_COMPONENT_LEGACY_HAL=legacy_hal
        SL_CATALOG_EMLIB_RMU_PRESENT
        SL_CATALOG_LEGACY_HAL_PRESENT
        SL_CATALOG_LEGACY_HAL_SOC_PRESENT
      )
    endif()

    if(EXISTS ${TOKEN_MANAGER_DIR}/inc/sl_token_manager_api.h)
      zephyr_include_directories(
        ${TOKEN_MANAGER_DIR}/config
        ${TOKEN_MANAGER_DIR}/inc
        ${TOKEN_MANAGER_DIR}/legacy/inc
      )

      zephyr_compile_definitions(
        SL_COMMON_TOKEN_MANAGER_ENABLE_DYNAMIC_TOKENS=1
        SL_COMMON_TOKEN_MANAGER_ENABLE_STATIC_TOKENS=1
        CUSTOM_TOKEN_HEADER=\"sl_token_manager_af_token_header.h\"
        SL_CATALOG_COMMON_TOKEN_MANAGER_PRESENT
        SL_CODE_COMPONENT_COMMON_TOKEN_MANAGER=common_token_manager
      )
    endif()

    if(EXISTS ${SECURITY_MANAGER_DIR}/security_manager.h)
      zephyr_include_directories(${SECURITY_MANAGER_DIR})
      zephyr_library_include_directories(
        ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/security/sl_component/sl_psa_driver/inc
        ${ZEPHYR_HAL_SILABS_MODULE_DIR}/simplicity_sdk/platform/security/sl_component/sl_mbedtls_support/inc
        ${ZEPHYR_BASE}/../modules/crypto/tf-psa-crypto/core
      )
  zephyr_library_sources_ifdef(CONFIG_SILABS_SISDK_ZIGBEE_SECURITY_MANAGER
    ${SECURITY_MANAGER_DIR}/security_manager.c
    ${SECURITY_DIR}/sl_component/sl_mbedtls_support/src/sl_psa_crypto.c
    zigbee/src/sl_psa_its_zephyr_shim.c
  )
      zephyr_compile_definitions_ifdef(CONFIG_SILABS_SISDK_ZIGBEE_SECURITY_MANAGER
        SL_CATALOG_SECURITY_MANAGER_PRESENT
      )
    endif()

    zephyr_include_directories(
      ${ZIGBEE_DIR}/app/framework/common
      ${ZIGBEE_DIR}/app/framework/include
      ${ZIGBEE_DIR}/app/framework/security
      ${ZIGBEE_DIR}/app/framework/util
      ${ZIGBEE_DIR}/platform/base/include
      ${ZIGBEE_DIR}/platform/radio
      ${ZIGBEE_DIR}/stack/include
    )
  endif()
endif()
