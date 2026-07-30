# Copyright (c) 2026 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

set(CONF_FILE "prj_z3_light_components.conf;prj.conf" CACHE STRING "Zigbee sample configs" FORCE)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(zigbee_z3_light)

# SDK/framework sources (hal_silabs) include zap-config.h via af.h; expose
# app autogen globally, not only on the app target.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/autogen)

target_sources(app PRIVATE
  src/main.c
  autogen/zap-event.c
  autogen/zap-cluster-command-parser.c
  autogen/sl_cluster_service_gen.c
  autogen/zigbee_stack_callback_dispatcher.c
  autogen/zigbee_zcl_callback_dispatcher.c
  autogen/zigbee_common_callback_dispatcher.c
)
