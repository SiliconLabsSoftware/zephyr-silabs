# Copyright (c) 2026 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

set(CONF_FILE "prj_z3_light_components.conf;prj.conf" CACHE STRING "Zigbee sample configs" FORCE)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(zigbee_z3_light)

# ZAP / Studio CLI autogen is MSLA content and lives in hal_silabs_extra.
if(NOT DEFINED ZEPHYR_HAL_SILABS_EXTRA_MODULE_DIR)
  message(FATAL_ERROR
    "zigbee_z3_light requires the hal_silabs_extra module "
    "(ZAP autogen under samples/zigbee_z3_light/autogen/).")
endif()

set(Z3_LIGHT_AUTOGEN
  ${ZEPHYR_HAL_SILABS_EXTRA_MODULE_DIR}/samples/zigbee_z3_light/autogen)

# SDK/framework sources include zap-config.h via af.h; expose app autogen
# globally, not only on the app target.
zephyr_include_directories(${Z3_LIGHT_AUTOGEN})

target_sources(app PRIVATE
  src/main.c
  src/app.c
  ${Z3_LIGHT_AUTOGEN}/zap-event.c
  ${Z3_LIGHT_AUTOGEN}/zap-cluster-command-parser.c
  ${Z3_LIGHT_AUTOGEN}/sl_cluster_service_gen.c
  ${Z3_LIGHT_AUTOGEN}/zigbee_stack_callback_dispatcher.c
  ${Z3_LIGHT_AUTOGEN}/zigbee_zcl_callback_dispatcher.c
  ${Z3_LIGHT_AUTOGEN}/zigbee_common_callback_dispatcher.c
)

if(CONFIG_SILABS_SISDK_CLI)
  target_sources(app PRIVATE
    src/zigbee_shell.c
    src/sl_cli_phase_a_stubs.c
    ${Z3_LIGHT_AUTOGEN}/sl_cli_command_table.c
    ${Z3_LIGHT_AUTOGEN}/zap-cli.c
  )
endif()
