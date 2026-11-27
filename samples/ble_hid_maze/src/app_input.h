/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_INPUT_H_
#define APP_INPUT_H_

#include <zephyr/kernel.h>

#include "app_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct app_input_event {
	int16_t dx;
	int16_t dy;
	bool left_pressed;
	bool right_pressed;
};

/* Initialize once before submitting reports or consuming events. */
void app_input_init(void);

/*
 * Convert button states to press events before queuing the report.
 * The mouse producer serializes submissions and app_input_reset_mouse().
 */
int app_input_submit_mouse(const struct mouse_data_element *mouse_data);

int app_input_get_event(struct app_input_event *event, k_timeout_t timeout);

/* Start a new mouse session: discard queued events and reset button history. */
void app_input_reset_mouse(void);

/* Discard queued events while retaining the current button history. */
void app_input_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_INPUT_H_ */
