/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Initialize the SiSDK sl_cli handle and default command group before AF
 * init_done. Zephyr Shell is the interactive front-end (see zigbee_shell.c).
 */

#include <string.h>

#include <zephyr/logging/log.h>

#include "sl_cli.h"
#include "sl_cli_zephyr_runtime.h"
#include "sl_status.h"

LOG_MODULE_REGISTER(silabs_cli_runtime, CONFIG_LOG_DEFAULT_LEVEL);

/* Provided by the app (e.g. Studio/SLC-generated sl_cli_command_table.c). */
extern const sl_cli_command_entry_t sl_cli_default_command_table[];

static sl_cli_t sl_cli_zephyr;
static sl_cli_command_group_t sl_cli_zephyr_command_group = {
	{ NULL },
	false,
	sl_cli_default_command_table
};

/* Consumed by Zigbee AF (e.g. sli_zigbee_zcl_cli_init). */
const sl_cli_handle_t sl_cli_handles[] = {
	&sl_cli_zephyr,
};
const uint32_t sl_cli_handles_count = sizeof(sl_cli_handles) / sizeof(sl_cli_handle_t);

static bool cli_runtime_ready;

sl_status_t sl_cli_zephyr_runtime_init(void)
{
	sl_cli_instance_parameters_t instance_parameters;

	if (cli_runtime_ready) {
		return SL_STATUS_OK;
	}

	/*
	 * Must run before Zigbee AF init_done so sli_zigbee_zcl_cli_init can
	 * attach the ZCL command group to the default CLI instance.
	 */
	memset(&instance_parameters, 0, sizeof(instance_parameters));

	sl_cli_default_handle = &sl_cli_zephyr;
	sl_cli_default_command_group = &sl_cli_zephyr_command_group;

	instance_parameters.task_name = "zephyr_cli";
	instance_parameters.iostream_handle = NULL;
	instance_parameters.default_command_group = sl_cli_default_command_group;

	sl_cli_instance_init(&sl_cli_zephyr, &instance_parameters);

	cli_runtime_ready = true;
	LOG_INF("SiSDK CLI command dispatcher initialized (Zephyr Shell front-end)");
	return SL_STATUS_OK;
}
