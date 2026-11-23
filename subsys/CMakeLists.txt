# Copyright (c) 2026 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory_ifdef(CONFIG_SILABS_SISDK_CLI sl_cli)
add_subdirectory_ifdef(CONFIG_SILABS_ZIGBEE_TOKEN_NVS sl_token_manager)
add_subdirectory(zigbee)
