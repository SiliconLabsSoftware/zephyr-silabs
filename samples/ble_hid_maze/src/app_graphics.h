/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_GRAPHICS_H_
#define APP_GRAPHICS_H_

#include <stdint.h>

#include "app_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int app_graphics_init(void);
int app_graphics_load_background(void);
int app_graphics_draw_marker(uint16_t x, uint16_t y);
void app_graphics_canvas_draw(uint16_t x, uint16_t y);
void app_graphics_canvas_clear(void);
void app_graphics_next_background(void);
enum touch_element app_graphics_marker_touching(uint16_t x, uint16_t y);

#ifdef __cplusplus
}
#endif

#endif /* APP_GRAPHICS_H_ */
