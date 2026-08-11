/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_TYPES_H_
#define APP_TYPES_H_

#include <stdbool.h>
#include <stdint.h>

struct int16_xy_pair {
	int16_t x;
	int16_t y;
};

struct mouse_data_element {
	int16_t dx;
	int16_t dy;
	bool left_button;
	bool right_button;
};

/* Common header used by the variable-sized GIMP C-source images. */
struct c_image {
	unsigned int width;
	unsigned int height;
	unsigned int bytes_per_pixel;
	const char *comment;
	unsigned char pixel_data[];
};

enum touch_element {
	TOUCH_BACKGROUND,
	TOUCH_WALL,
	TOUCH_FINISH_LINE,
	TOUCH_DISPLAY_BORDER,
};

#endif /* APP_TYPES_H_ */
