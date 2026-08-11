/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "app_graphics_marker.h"

#if (DISPLAY_W <= 64) || (DISPLAY_H <= 64)
/* Tiny displays (radius 3) */
const struct int16_xy_pair marker_draw_buffer_segment_xy[] = {{-1, -1}};
const struct int16_xy_pair marker_draw_buffer_segment_dimensions[] = {{3, 3}};

const struct int16_xy_pair marker_draw_buffer_border[] = {{-1, -1}, {0, -1}, {1, -1}, {-1, 0},
							  {1, 0},   {-1, 1}, {0, 1},  {1, 1}};

#elif (DISPLAY_W <= 128) || (DISPLAY_H <= 128)
/* Small displays (radius 5) */
const struct int16_xy_pair marker_draw_buffer_segment_xy[] = {{-1, -2}, {-2, -1}};
const struct int16_xy_pair marker_draw_buffer_segment_dimensions[] = {{3, 5}, {5, 3}};

const struct int16_xy_pair marker_draw_buffer_border[] = {{-1, -2}, {0, -2}, {1, -2}, {-2, -1},
							  {2, -1},  {-2, 0}, {2, 0},  {-2, 1},
							  {2, 1},   {-1, 2}, {0, 2},  {1, 2}};

#elif (DISPLAY_W <= 320) || (DISPLAY_H <= 320)
/* Medium displays (radius 9) */
const struct int16_xy_pair marker_draw_buffer_segment_xy[] = {{-3, -3}, {-2, -4}, {-4, -2}};
const struct int16_xy_pair marker_draw_buffer_segment_dimensions[] = {{7, 7}, {5, 9}, {9, 5}};
const struct int16_xy_pair marker_draw_buffer_border[] = {
	{-2, -4}, {-1, -4}, {0, -4}, {1, -4}, {2, -4}, {-3, -3}, {3, -3}, {-4, -2},
	{4, -2},  {-4, -1}, {4, -1}, {-4, 0}, {4, 0},  {-4, 1},  {4, 1},  {-4, 2},
	{4, 2},   {-3, 3},  {3, 3},  {-2, 4}, {-1, 4}, {0, 4},   {1, 4},  {2, 4}};

#else
/* Large displays (radius 11) */
const struct int16_xy_pair marker_draw_buffer_segment_xy[] = {
	{-2, -5}, {-3, -4}, {-4, -3}, {-5, -2}};
const struct int16_xy_pair marker_draw_buffer_segment_dimensions[] = {
	{5, 11}, {7, 9}, {9, 7}, {11, 5}};
const struct int16_xy_pair marker_draw_buffer_border[] = {
	{-2, -5}, {-1, -5}, {0, -5},  {1, -5}, {2, -5},  {-3, -4}, {3, -4},
	{-4, -3}, {4, -3},  {-5, -2}, {5, -2}, {-5, -1}, {5, -1},  {-5, 0},
	{5, 0},   {-5, 1},  {5, 1},   {-5, 2}, {5, 2},   {-4, 3},  {4, 3},
	{-3, 4},  {3, 4},   {-2, 5},  {-1, 5}, {0, 5},   {1, 5},   {2, 5}};

#endif
