/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr Shell bridge: forward "zigbee <sl-cli-line>" to sl_cli_command_execute().
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>

#include "sl_cli.h"
#include "sl_cli_command.h"
#include "sl_cli_config.h"
#include "sl_cli_io_zephyr.h"
#include "sl_status.h"

#ifndef ZIGBEE_SHELL_LINE_MAX
#define ZIGBEE_SHELL_LINE_MAX SL_CLI_INPUT_BUFFER_SIZE
#endif

static int cmd_zigbee(const struct shell *sh, size_t argc, char **argv)
{
	char line[ZIGBEE_SHELL_LINE_MAX];
	size_t pos = 0U;
	sl_status_t status;

	if (argc < 2U) {
		shell_print(sh, "usage: zigbee <sl-cli-command> [args...]");
		return -EINVAL;
	}

	if (sl_cli_default_handle == NULL) {
		shell_error(sh, "Zigbee CLI not initialized");
		return -ENODEV;
	}

	line[0] = '\0';
	for (size_t i = 1U; i < argc; i++) {
		int n;

		if (i > 1U) {
			if (pos + 1U >= sizeof(line)) {
				shell_error(sh, "command too long");
				return -EINVAL;
			}
			line[pos++] = ' ';
			line[pos] = '\0';
		}

		n = snprintf(&line[pos], sizeof(line) - pos, "%s", argv[i]);
		if (n < 0 || (size_t)n >= (sizeof(line) - pos)) {
			shell_error(sh, "command too long");
			return -EINVAL;
		}
		pos += (size_t)n;
	}

	sl_cli_io_zephyr_set_shell(sh);
	status = sl_cli_command_execute(sl_cli_default_handle, line);
	sl_cli_io_zephyr_set_shell(NULL);

	if (status == SL_STATUS_OK) {
		return 0;
	}
	if (status == SL_STATUS_NOT_FOUND) {
		shell_error(sh, "unknown command");
		return -ENOENT;
	}

	shell_error(sh, "command failed: 0x%04x", status);
	return -EIO;
}

SHELL_CMD_ARG_REGISTER(zigbee, NULL, "Zigbee SL CLI (info, network, zcl, ...)",
		       cmd_zigbee, 2, 32);
