# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0
#
# This CMake file is picked by the Zephyr build system because it is defined
# as the module CMake entry point (see zephyr/module.yml).

add_subdirectory(drivers)
add_subdirectory(modules)

if(DEFINED CONFIG_SOC_FAMILY_SILABS_S2)

# If MCUboot is being built, use the Commander signing script to sign the bootloader
# with Simplicity Commander. This enables the MCUboot image to be secure boot
# verified by the SE.
if(DEFINED CONFIG_MCUBOOT)
  set_target_properties(zephyr_property_target PROPERTIES
    SIGNING_SCRIPT ${CMAKE_CURRENT_LIST_DIR}/zephyr/cmake/commander_sign.cmake
  )
endif()

endif()
