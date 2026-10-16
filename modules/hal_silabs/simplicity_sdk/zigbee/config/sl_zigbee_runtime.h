/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr runtime glue for the Silicon Labs Zigbee stack and application
 * framework. Replaces Simplicity Studio sl_main event_handler dispatch.
 */

#ifndef SL_ZIGBEE_RUNTIME_H
#define SL_ZIGBEE_RUNTIME_H

#include <stdint.h>

#include "sl_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize secure key storage upgrade, stack, and application framework. */
sl_status_t sl_zigbee_runtime_init(void);

/** Run one stack tick followed by one application framework tick. */
void sl_zigbee_runtime_process_once(void);

/** Milliseconds to sleep before the next process_once call. */
uint32_t sl_zigbee_runtime_ms_until_next_tick(void);

/** Start the dedicated Zigbee processing thread (optional). */
sl_status_t sl_zigbee_runtime_start(void);

#ifdef __cplusplus
}
#endif

#endif /* SL_ZIGBEE_RUNTIME_H */
