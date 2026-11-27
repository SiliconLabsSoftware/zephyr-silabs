/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_GRAPHICS_MARKER_H_
#define APP_GRAPHICS_MARKER_H_

#include <zephyr/kernel.h>
#include "app_display.h"
#include "app_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct int16_xy_pair marker_draw_buffer_segment_xy[];
extern const struct int16_xy_pair marker_draw_buffer_segment_dimensions[];
extern const struct int16_xy_pair marker_draw_buffer_border[];

#if (DISPLAY_W <= 64) || (DISPLAY_H <= 64)
/* Tiny displays (radius 3). */
#define LINE_WIDTH                          1
#define MARKER_BUF_DIM                      9
#define MARKER_BUF_MIN_WIDTH                5
#define MARKER_BUF_MIN_HEIGHT               5
#define MARKER_DRAW_BUFFER_BORDER_ELEMENTS  8
#define MARKER_DRAW_BUFFER_SEGMENT_ELEMENTS 1

#elif (DISPLAY_W <= 128) || (DISPLAY_H <= 128)
/* Small displays (radius 5). */
#define LINE_WIDTH                          1
#define MARKER_BUF_DIM                      9
#define MARKER_BUF_MIN_WIDTH                7
#define MARKER_BUF_MIN_HEIGHT               7
#define MARKER_DRAW_BUFFER_SEGMENT_ELEMENTS 2
#define MARKER_DRAW_BUFFER_BORDER_ELEMENTS  12

#elif (DISPLAY_W <= 320) || (DISPLAY_H <= 320)
/* Medium displays (radius 9). */
#define LINE_WIDTH                          3
#define MARKER_BUF_DIM                      21
#define MARKER_BUF_MIN_WIDTH                9
#define MARKER_BUF_MIN_HEIGHT               9
#define MARKER_DRAW_BUFFER_SEGMENT_ELEMENTS 3
#define MARKER_DRAW_BUFFER_BORDER_ELEMENTS  24

#else
/* Large displays (radius 11). */
#define LINE_WIDTH                          5
#define MARKER_BUF_DIM                      21
#define MARKER_BUF_MIN_WIDTH                13
#define MARKER_BUF_MIN_HEIGHT               13
#define MARKER_DRAW_BUFFER_SEGMENT_ELEMENTS 4
#define MARKER_DRAW_BUFFER_BORDER_ELEMENTS  28

#endif

#define MAX_MOVEMENT_WITHOUT_UPDATE ((MARKER_BUF_DIM - MARKER_BUF_MIN_WIDTH) / 2)

#ifdef __cplusplus
}
#endif

#endif /* APP_GRAPHICS_MARKER_H_ */
