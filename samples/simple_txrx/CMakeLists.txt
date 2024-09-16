# Copyright (c) 2023 Silicon Laboratories Inc.
# SPDX-License-Identifier: Zlib

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(simple_txrx)

target_include_directories(app PRIVATE
    src/rail-configs/${CONFIG_BOARD}
)
target_sources(app PRIVATE
    src/main.c
    src/rail-configs/${CONFIG_BOARD}/rail_config.c
)
