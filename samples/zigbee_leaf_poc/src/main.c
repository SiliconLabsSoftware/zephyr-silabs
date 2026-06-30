/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(zigbee_leaf_poc, LOG_LEVEL_INF);

int main(void)
{
	LOG_INF("Silicon Labs Zigbee leaf PoC");
	LOG_INF("Prebuilt stack libraries are linked via CONFIG_ZIGBEE_SILABS");
	LOG_INF("Add Zigbee SDK sources and runtime glue for a functional network");

	while (true) {
		k_sleep(K_SECONDS(5));
	}

	return 0;
}
