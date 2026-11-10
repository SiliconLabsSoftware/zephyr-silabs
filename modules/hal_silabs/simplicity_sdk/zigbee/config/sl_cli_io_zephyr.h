/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Bind sli_cli_io_* output to an active Zephyr Shell for the duration of a
 * zigbee shell command.
 */

#ifndef SL_CLI_IO_ZEPHYR_H
#define SL_CLI_IO_ZEPHYR_H

#include <zephyr/shell/shell.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Route subsequent sli_cli_io_printf/putchar to this shell (or NULL = printk). */
void sl_cli_io_zephyr_set_shell(const struct shell *sh);

#ifdef __cplusplus
}
#endif

#endif /* SL_CLI_IO_ZEPHYR_H */
