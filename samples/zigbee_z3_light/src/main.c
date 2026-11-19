/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "sl_status.h"
#include "sl_zigbee_runtime.h"

LOG_MODULE_REGISTER(zigbee_z3_light, LOG_LEVEL_INF);

int main(void)
{
	sl_status_t status;

	LOG_INF("Silicon Labs Zigbee Z3 Light");

	status = sl_zigbee_runtime_init();
	if (status != SL_STATUS_OK) {
		LOG_ERR("Zigbee runtime init failed: 0x%04x", status);
		return 1;
	}

#if defined(CONFIG_SILABS_ZIGBEE_RUNTIME_THREAD)
	status = sl_zigbee_runtime_start();
	if (status != SL_STATUS_OK) {
		LOG_ERR("Zigbee runtime thread start failed: 0x%04x", status);
		return 1;
	}
#endif

	while (true) {
#if !defined(CONFIG_SILABS_ZIGBEE_RUNTIME_THREAD)
		sl_zigbee_runtime_process_once();
		k_msleep(sl_zigbee_runtime_ms_until_next_tick());
#else
		k_sleep(K_FOREVER);
#endif
	}

	return 0;
}
