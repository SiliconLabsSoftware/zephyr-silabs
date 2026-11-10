/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal led.h so SDK legacy_hal/hal.h can include it without pulling
 * Silicon Labs LED APIs. Activity indication uses Zephyr GPIO (led0).
 */

#ifndef __LED_H__
#define __LED_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Configure GPIOs used for stack activity indication. */
void halInternalInitLed(void);

/**
 * Called by the stack to indicate radio activity (TX). Once with turnOn
 * true, shortly thereafter with turnOn false.
 */
void halStackIndicateActivity(bool turnOn);

#ifdef __cplusplus
}
#endif

#endif /* __LED_H__ */
