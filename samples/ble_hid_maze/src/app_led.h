/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_LED_H_
#define APP_LED_H_

int app_led_init(void);

int app_led_on(void);
int app_led_off(void);
int app_led_blink_slow(void);
int app_led_blink_fast(void);
int app_led_heartbeat(void);

#endif /* APP_LED_H_ */
