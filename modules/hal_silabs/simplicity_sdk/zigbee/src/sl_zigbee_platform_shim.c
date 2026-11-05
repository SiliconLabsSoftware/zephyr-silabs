/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/__assert.h>

void halInternalAssertFailed(const char *filename, int linenumber)
{
	__ASSERT(false, "Zigbee HAL assert at %s:%d", filename, linenumber);
}
