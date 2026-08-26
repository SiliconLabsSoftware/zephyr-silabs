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

void app_input_init(void);

int app_input_submit_mouse(const struct mouse_data_element *mouse_data);

int app_input_get_mouse(struct mouse_data_element *mouse_data, k_timeout_t timeout);

void app_input_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_INPUT_H_ */
