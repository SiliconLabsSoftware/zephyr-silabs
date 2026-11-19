/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SL_CLI_ZEPHYR_RUNTIME_H
#define SL_CLI_ZEPHYR_RUNTIME_H

#include "sl_cli.h"
#include "sl_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize sl_cli handle and default command group (no tick thread). */
sl_status_t sl_cli_zephyr_runtime_init(void);

/** Single Zephyr CLI instance; used by Zigbee AF to attach command groups. */
extern const sl_cli_handle_t sl_cli_handles[];
extern const uint32_t sl_cli_handles_count;

#ifdef __cplusplus
}
#endif

#endif /* SL_CLI_ZEPHYR_RUNTIME_H */
