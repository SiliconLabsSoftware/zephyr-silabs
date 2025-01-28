# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory_ifdef(CONFIG_SOC_FAMILY_SILABS_S2 simplicity_sdk)
add_subdirectory_ifdef(CONFIG_HAS_SILABS_WISECONNECT wiseconnect)
