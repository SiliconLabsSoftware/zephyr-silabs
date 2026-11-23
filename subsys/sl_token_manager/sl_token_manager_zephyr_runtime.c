/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Initialize Common Token Manager before Zigbee stack init. Registered via
 * SYS_INIT so sl_zigbee_runtime_glue does not own CTM bring-up.
 */

#include <errno.h>

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include "sl_status.h"
#include "sl_token_manager_api.h"

LOG_MODULE_REGISTER(silabs_token_runtime, CONFIG_LOG_DEFAULT_LEVEL);

static int sl_token_manager_zephyr_sys_init(void)
{
	sl_status_t status = sl_token_manager_init();

	if (status != SL_STATUS_OK) {
		LOG_ERR("sl_token_manager_init failed: 0x%04x", status);
		return -EIO;
	}

	return 0;
}

/*
 * APPLICATION runs after POST_KERNEL (CTM lock mutex SYS_INIT) and before
 * main() / sl_zigbee_runtime_init(), matching Studio early CTM bring-up.
 */
SYS_INIT(sl_token_manager_zephyr_sys_init, APPLICATION, 0);
