# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wifi_provisioning_over_ble)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../modules/wifi_app_util ${CMAKE_CURRENT_BINARY_DIR}/wifi_app_util)
target_sources(app PRIVATE src/main.c)
target_link_libraries(app PRIVATE wifi_app_util)
