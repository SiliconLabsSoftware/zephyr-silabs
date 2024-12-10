# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

set(COMMON_DIR       ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect/components/common)
set(DEVICE_DIR       ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect/components/device)
set(SERVICE_DIR      ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect/components/service)
set(PROTOCOL_DIR     ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect/components/protocol)
set(DEFAULTS_DIR     ${ZEPHYR_HAL_SILABS_MODULE_DIR}/wiseconnect/resources/defaults)
set(GECKO_COMMON_DIR ${ZEPHYR_HAL_SILABS_MODULE_DIR}/gecko/common)

zephyr_include_directories(
  ${GECKO_COMMON_DIR}/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/core/config
  ${DEVICE_DIR}/silabs/si91x/mcu/core/chip/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/rom_driver/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/peripheral_drivers/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/service/clock_manager/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/systemlevel/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/unified_api/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/unified_peripheral_drivers/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/cmsis_driver/config
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/cmsis_driver
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/cmsis_driver/CMSIS/Driver/Include
)

# Keep these values sync with
# components/device/silabs/si91x/mcu/core/chip/component/siwg917*.slcc
zephyr_compile_definitions(
  SL_SI91X_ENABLE_LITTLE_ENDIAN
  SLI_SI91X_MCU_CONFIG_RADIO_BOARD_VER2
  SLI_SI91X_MCU_CONFIG_RADIO_BOARD_BASE_VER
  SLI_SI91X_MCU_ENABLE_FLASH_BASED_EXECUTION
  SLI_SI91X_MCU_ENABLE_IPMU_APIS
  SLI_SI91X_MCU_INTERFACE
  SLI_SI917
  SLI_SI917B0
  CLOCK_ROMDRIVER_PRESENT
)

zephyr_compile_definitions_ifdef(CONFIG_SIWX917_FLASH_MODE_COMMON
  SLI_SI91X_MCU_COMMON_FLASH_MODE=1
)

zephyr_library_sources(
  ${DEVICE_DIR}/silabs/si91x/mcu/core/chip/src/rsi_deepsleep_soc.c
  ${DEVICE_DIR}/silabs/si91x/mcu/core/chip/src/system_si91x.c
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/systemlevel/src/rsi_ipmu.c
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/systemlevel/src/rsi_pll.c
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/systemlevel/src/rsi_ulpss_clk.c
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/service/clock_manager/src/sl_si91x_clock_manager.c
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/unified_api/src/sl_si91x_driver_gpio.c
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/unified_peripheral_drivers/src/sl_si91x_peripheral_gpio.c
  ${DEVICE_DIR}/silabs/si91x/mcu/core/chip/src/iPMU_prog/iPMU_dotc/ipmu_apis.c
  ${DEVICE_DIR}/silabs/si91x/mcu/core/chip/src/iPMU_prog/iPMU_dotc/rsi_system_config_917.c
)

zephyr_library_sources_ifdef(CONFIG_ENTROPY_SILABS_SIWX917
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/peripheral_drivers/src/rsi_rng.c
)

zephyr_library_sources_ifdef(CONFIG_DMA_SILABS_SIWX917
  ${DEVICE_DIR}/silabs/si91x/mcu/drivers/rom_driver/src/rsi_rom_table_si91x.c
)

zephyr_compile_definitions_ifdef(CONFIG_DMA_SILABS_SIWX917
  UDMA_ROMDRIVER_PRESENT
)

if(CONFIG_WIFI_SIWX917)

zephyr_compile_definitions_ifdef(CONFIG_NET_IPV6
  SLI_SI91X_ENABLE_IPV6
)
zephyr_compile_definitions_ifdef(CONFIG_WIFI_SIWX917_NET_STACK_OFFLOAD
  SLI_SI91X_OFFLOAD_NETWORK_STACK
  SLI_SI91X_SOCKETS
)
zephyr_include_directories(
  ${DEFAULTS_DIR}
)
zephyr_library_sources(
  ${DEVICE_DIR}/silabs/si91x/wireless/sl_net/src/sl_si91x_net_credentials.c
  ${DEVICE_DIR}/silabs/si91x/wireless/sl_net/src/sl_si91x_net_internal_stack.c
  ${DEVICE_DIR}/silabs/si91x/wireless/sl_net/src/sl_net_si91x_integration_handler.c
  ${DEVICE_DIR}/silabs/si91x/wireless/sl_net/src/sl_net_rsi_utility.c
  ${DEVICE_DIR}/silabs/si91x/wireless/socket/src/sl_si91x_socket_utility.c
  ${DEVICE_DIR}/silabs/si91x/wireless/asynchronous_socket/src/sl_si91x_socket.c
  ${SERVICE_DIR}/network_manager/si91x/sl_net_si91x.c
  ${SERVICE_DIR}/network_manager/src/sl_net_basic_credentials.c
  ${SERVICE_DIR}/network_manager/src/sl_net_basic_profiles.c
  ${SERVICE_DIR}/network_manager/src/sl_net.c
)

endif() # CONFIG_WIFI_SIWX917

zephyr_compile_definitions_ifdef(CONFIG_BT_SIWX917
  SLI_SI91X_ENABLE_BLE=1
)
zephyr_include_directories_ifdef(CONFIG_BT_SIWX917
  ${DEVICE_DIR}/silabs/si91x/wireless/ble/inc
)
zephyr_library_sources_ifdef(CONFIG_BT_SIWX917
  ${DEVICE_DIR}/silabs/si91x/wireless/ble/src/rsi_bt_ble.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ble/src/rsi_common_apis.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ble/src/rsi_utils.c
)

zephyr_include_directories_ifdef(CONFIG_WISECONNECT_NETWORK_STACK
  # FIXME: find why this directory is not included when CMSIS_RTOS_V2=y
  ${ZEPHYR_BASE}/include/zephyr/posix
  ${ZEPHYR_BASE}/include/zephyr/portability
  ${COMMON_DIR}/inc
  ${DEVICE_DIR}/silabs/si91x/wireless/inc
  ${DEVICE_DIR}/silabs/si91x/wireless/sl_net/inc
  ${DEVICE_DIR}/silabs/si91x/wireless/socket/inc
  ${DEVICE_DIR}/silabs/si91x/wireless/asynchronous_socket/inc
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/inc
  ${DEVICE_DIR}/silabs/si91x/mcu/core/chip/config
  ${PROTOCOL_DIR}/wifi/inc
  ${SERVICE_DIR}/network_manager/inc
)
zephyr_compile_definitions_ifdef(CONFIG_WISECONNECT_NETWORK_STACK
    SLI_SI91X_ENABLE_OS
    SL_SI91X_SI917_RAM_MEM_CONFIG=1
    SL_WIFI_COMPONENT_INCLUDED #Needed for BT as well...
)
zephyr_library_sources_ifdef(CONFIG_WISECONNECT_NETWORK_STACK
  ${COMMON_DIR}/src/sl_utility.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/src/rsi_hal_mcu_m4_ram.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/src/rsi_hal_mcu_m4_rom.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/src/sli_siwx917_soc.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/src/sl_platform.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/src/sl_platform_wireless.c
  ${DEVICE_DIR}/silabs/si91x/wireless/ahb_interface/src/sl_si91x_bus.c
  ${DEVICE_DIR}/silabs/si91x/wireless/host_mcu/si91x/siwx917_soc_ncp_host.c
  ${DEVICE_DIR}/silabs/si91x/wireless/memory/malloc_buffers.c
  ${DEVICE_DIR}/silabs/si91x/wireless/src/sl_rsi_utility.c
  ${DEVICE_DIR}/silabs/si91x/wireless/src/sl_si91x_callback_framework.c
  ${DEVICE_DIR}/silabs/si91x/wireless/src/sl_si91x_driver.c
  ${DEVICE_DIR}/silabs/si91x/wireless/threading/sli_si91x_multithreaded.c
  ${PROTOCOL_DIR}/wifi/si91x/sl_wifi.c
  ${PROTOCOL_DIR}/wifi/src/sl_wifi_callback_framework.c
)
