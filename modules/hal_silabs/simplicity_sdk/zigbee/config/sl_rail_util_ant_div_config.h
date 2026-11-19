/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal antenna-diversity config for boards without external ant-div GPIOs.
 * Compiles the disabled path in sl_rail_util_ant_div.c (init returns OK).
 *
 * Values match SL_RAIL_UTIL_ANTENNA_MODE_* / SL_RAIL_UTIL_ANT_DIV_* enums
 * from sl_rail_util_ant_div.h (0 = disabled).
 */

#ifndef SL_RAIL_UTIL_ANT_DIV_CONFIG_H
#define SL_RAIL_UTIL_ANT_DIV_CONFIG_H

#define SL_RAIL_UTIL_ANT_DIV_DISABLED  (0U)
#define SL_RAIL_UTIL_ANT_DIV_ANTENNA0  (1U)
#define SL_RAIL_UTIL_ANT_DIV_ANTENNA1  (2U)
#define SL_RAIL_UTIL_ANT_DIV_DIVERSITY (3U)

#define SL_RAIL_UTIL_ANT_DIV_RX_MODE  SL_RAIL_UTIL_ANT_DIV_DISABLED
#define SL_RAIL_UTIL_ANT_DIV_TX_MODE  SL_RAIL_UTIL_ANT_DIV_DISABLED
#define SL_RAIL_UTIL_ANT_DIV_RX_RUNTIME_PHY_SELECT 0

#define SL_RAIL_UTIL_ANTENNA_RX_DEFAULT_MODE 0 /* SL_RAIL_UTIL_ANTENNA_MODE_DISABLED */
#define SL_RAIL_UTIL_ANTENNA_TX_DEFAULT_MODE 0 /* SL_RAIL_UTIL_ANTENNA_MODE_DISABLED */

#endif /* SL_RAIL_UTIL_ANT_DIV_CONFIG_H */
