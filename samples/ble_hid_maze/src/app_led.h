/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_LED_H_
#define APP_LED_H_

/* Initialize once before requesting a pattern. */
int app_led_init(void);

enum app_led_pattern {
	APP_LED_PATTERN_OFF,
	APP_LED_PATTERN_ON,
	APP_LED_PATTERN_BLINK_SLOW,
	APP_LED_PATTERN_BLINK_FAST,
	APP_LED_PATTERN_HEARTBEAT,
};

/*
 * Request a pattern asynchronously, restarting it from its first step.
 * The latest request wins if several arrive before the worker runs.
 * Returns 0 when accepted, -EINVAL for an unknown pattern, -EAGAIN before
 * initialization, or a workqueue submission error. GPIO errors are logged
 * by the worker and stop playback until another pattern is requested.
 */
int app_led_set_pattern(enum app_led_pattern pattern);

#endif /* APP_LED_H_ */
