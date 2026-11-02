/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include "app_graphics.h"
#include "app_graphics_marker.h"
#include "app_display.h"
#include <zephyr/drivers/display.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(app_graphics, LOG_LEVEL_INF);

#define BACKGROUND_COUNT 3

#define RGB_TO_RGB565(r, g, b)                                                                     \
	((((uint16_t)(r) >> 3) << 11) | (((uint16_t)(g) >> 2) << 5) | ((uint16_t)(b) >> 3))
#define COLOR_RGB_565_BLACK  0x0000U
#define COLOR_RGB_565_WHITE  0xffffU
#define COLOR_RGB_565_RED    RGB_TO_RGB565(255, 0, 0)
#define COLOR_RGB_565_GREEN  RGB_TO_RGB565(0, 255, 0)
#define COLOR_RGB_565_YELLOW RGB_TO_RGB565(255, 208, 84)

extern const struct c_image bg_hex;
extern const struct c_image bg_square;
extern const struct c_image bg_triangle;

static const struct device *const display_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_display));
static struct display_capabilities display_capabilities;

/* One bit per pixel is enough to retain the marker trail. */
static uint8_t canvas_bitmap[(DISPLAY_W * DISPLAY_H) / 8];

static size_t display_bits_per_pixel;

/* The display is updated one row at a time, avoiding a full RGB frame buffer. */
static uint8_t *display_row_buf;
static struct display_buffer_descriptor display_row_buf_desc;

/* Scratch buffer used to redraw the marker and its immediate surroundings. */
static uint8_t *marker_draw_buf;
static struct display_buffer_descriptor marker_draw_buf_desc;

static size_t game_background_id;
static const struct c_image *const game_backgrounds[BACKGROUND_COUNT] = {
	&bg_square,
	&bg_triangle,
	&bg_hex,
};
static const struct c_image *current_background;

static int (*load_background_fn)(void);
static int (*draw_marker_fn)(uint16_t x, uint16_t y);

static uint16_t bg_color;
static uint16_t marker_color;
static uint16_t line_color;
static uint16_t finish_color;

static int init_display_row_buf(void);
static int init_marker_draw_buf_mono(void);
static int init_marker_draw_buf_rgb565(void);
static void canvas_set_pixel(uint16_t x, uint16_t y);
static uint8_t canvas_get_pixel(uint16_t x, uint16_t y);
static int load_background_mono(void);
static int load_background_rgb565(void);
static int draw_marker_mono(uint16_t x, uint16_t y);
static int draw_marker_rgb565(uint16_t x, uint16_t y);

int app_graphics_init(void)
{
	int err;

	if (!device_is_ready(display_dev)) {
		LOG_ERR("Display device %s is not ready", display_dev->name);
		return -ENODEV;
	}

	display_get_capabilities(display_dev, &display_capabilities);
	LOG_INF("Display: %ux%u, pixel format 0x%04x", display_capabilities.x_resolution,
		display_capabilities.y_resolution, display_capabilities.current_pixel_format);

	switch (display_capabilities.current_pixel_format) {
	case PIXEL_FORMAT_MONO01:
	case PIXEL_FORMAT_MONO10:
		display_bits_per_pixel = 1;
		load_background_fn = load_background_mono;
		draw_marker_fn = draw_marker_mono;

		err = init_marker_draw_buf_mono();
		if (err) {
			return err;
		}
		err = init_display_row_buf();
		if (err) {
			return err;
		}

		bg_color = sys_cpu_to_be16(COLOR_RGB_565_BLACK);
		marker_color = sys_cpu_to_be16(COLOR_RGB_565_WHITE);
		line_color = sys_cpu_to_be16(COLOR_RGB_565_WHITE);
		finish_color = sys_cpu_to_be16(COLOR_RGB_565_GREEN);
		break;
	case PIXEL_FORMAT_RGB_565:
	case PIXEL_FORMAT_RGB_565X:
		display_bits_per_pixel = 16;
		load_background_fn = load_background_rgb565;
		draw_marker_fn = draw_marker_rgb565;

		err = init_marker_draw_buf_rgb565();
		if (err) {
			return err;
		}
		err = init_display_row_buf();
		if (err) {
			return err;
		}

		bg_color = sys_cpu_to_be16(COLOR_RGB_565_BLACK);
		marker_color = sys_cpu_to_be16(COLOR_RGB_565_RED);
		line_color = sys_cpu_to_be16(COLOR_RGB_565_YELLOW);
		finish_color = sys_cpu_to_be16(COLOR_RGB_565_GREEN);
		break;
	default:
		LOG_ERR("Unsupported display pixel format 0x%04x",
			display_capabilities.current_pixel_format);
		return -ENOTSUP;
	}

	game_background_id = 0;
	current_background = game_backgrounds[game_background_id];

	err = display_blanking_off(display_dev);
	if (err < 0) {
		LOG_ERR("Could not enable the display: %d", err);
		return err;
	}

	return 0;
}

void app_graphics_next_background(void)
{
	game_background_id = (game_background_id + 1) % ARRAY_SIZE(game_backgrounds);
	current_background = game_backgrounds[game_background_id];
	LOG_INF("Switched to background %u", game_background_id);
}

static int init_display_row_buf(void)
{

	LOG_INF("Graphics buffer init");
	display_row_buf = k_malloc(DISPLAY_W * display_bits_per_pixel / 8);
	if (display_row_buf == NULL) {
		LOG_ERR("Failed to allocate buffer for updating display.");
		return -ENOMEM;
	}

	display_row_buf_desc.frame_incomplete = false;
	display_row_buf_desc.pitch = DISPLAY_W;
	display_row_buf_desc.width = DISPLAY_W;
	display_row_buf_desc.height = 1;
	display_row_buf_desc.buf_size = DISPLAY_W * display_bits_per_pixel / 8;

	return 0;
}

static int init_marker_draw_buf_mono(void)
{
	LOG_INF("Draw buffer init");
	marker_draw_buf = k_malloc(DISPLAY_W * MARKER_BUF_DIM * display_bits_per_pixel / 8);
	if (marker_draw_buf == NULL) {
		LOG_ERR("Failed to allocate buffer for drawing marker.");
		return -ENOMEM;
	}

	marker_draw_buf_desc.frame_incomplete = false;
	marker_draw_buf_desc.pitch = DISPLAY_W;
	marker_draw_buf_desc.width = DISPLAY_W; /* same as display width */
	marker_draw_buf_desc.height = MARKER_BUF_DIM;
	marker_draw_buf_desc.buf_size = DISPLAY_W * MARKER_BUF_DIM * display_bits_per_pixel / 8;

	return 0;
}

static int init_marker_draw_buf_rgb565(void)
{
	LOG_INF("Draw buffer init");
	marker_draw_buf = k_malloc(MARKER_BUF_DIM * MARKER_BUF_DIM * display_bits_per_pixel / 8);
	if (marker_draw_buf == NULL) {
		LOG_ERR("Failed to allocate buffer for drawing marker.");
		return -ENOMEM;
	}

	marker_draw_buf_desc.frame_incomplete = false;
	marker_draw_buf_desc.pitch = MARKER_BUF_DIM;
	marker_draw_buf_desc.width = MARKER_BUF_DIM;
	marker_draw_buf_desc.height = MARKER_BUF_DIM;
	marker_draw_buf_desc.buf_size =
		MARKER_BUF_DIM * MARKER_BUF_DIM * display_bits_per_pixel / 8;

	return 0;
}

void app_graphics_canvas_clear(void)
{
	memset(canvas_bitmap, 0, sizeof(canvas_bitmap));
}

void app_graphics_canvas_draw(uint16_t x0, uint16_t y0)
{
	int16_t w = LINE_WIDTH / 2;

	for (int16_t y = -w; y <= w; y++) {
		for (int16_t x = -w; x <= w; x++) {
			canvas_set_pixel(x0 + x, y0 + y);
		}
	}
}

static void canvas_set_pixel(uint16_t x, uint16_t y)
{
	if (x >= DISPLAY_W || y >= DISPLAY_H) {
		return;
	}

	uint32_t bit_index = (uint32_t)y * DISPLAY_W + x;
	uint32_t byte_index = bit_index >> 3;  /* divide by 8 */
	uint8_t bit_offset = bit_index & 0x07; /* mod 8 */

	canvas_bitmap[byte_index] |= (1u << bit_offset);
}

static uint8_t canvas_get_pixel(uint16_t x, uint16_t y)
{
	if (x >= DISPLAY_W || y >= DISPLAY_H) {
		return 0;
	}

	uint32_t bit_index = (uint32_t)y * DISPLAY_W + x;
	uint32_t byte_index = bit_index >> 3;  /* divide by 8 */
	uint8_t bit_offset = bit_index & 0x07; /* mod 8 */

	return (canvas_bitmap[byte_index] >> bit_offset) & 1u;
}

static inline uint8_t canvas_get_pixel_inline(uint16_t x, uint16_t y)
{
	return (canvas_bitmap[y * (DISPLAY_W / 8) + (x >> 3)] >> (x & 7)) & 1u;
}

static inline bool rgb565_to_mono_dither(uint16_t rgb565, size_t x, size_t y)
{
	static const uint8_t bayer4x4[4][4] = {
		{0, 8, 2, 10},
		{12, 4, 14, 6},
		{3, 11, 1, 9},
		{15, 7, 13, 5},
	};

	uint8_t r = (rgb565 >> 11) & 0x1F;
	uint8_t g = (rgb565 >> 5) & 0x3F;
	uint8_t b = rgb565 & 0x1F;

	uint8_t r8 = (r << 3) | (r >> 2);
	uint8_t g8 = (g << 2) | (g >> 4);
	uint8_t b8 = (b << 3) | (b >> 2);

	/* Luma, approximately 0..255 */
	uint16_t luma = (30 * r8 + 59 * g8 + 11 * b8) / 100;

	/* Convert Bayer value 0..15 to threshold around 0..255 */
	uint8_t threshold = bayer4x4[y & 3][x & 3] * 16 + 8;

	return luma > threshold;
}

static int load_background_mono(void)
{
	const uint16_t *pixel_data_b16 = (const uint16_t *)current_background->pixel_data;
	uint8_t *row_buf = display_row_buf;
	int ret;

	LOG_INF("Loading background for monochrome display");

	for (size_t y = 0; y < DISPLAY_H; y++) {
		memset(row_buf, 0, display_row_buf_desc.buf_size);

		for (size_t x = 0; x < DISPLAY_W; x++) {
			uint16_t pixel = pixel_data_b16[x + y * DISPLAY_W];

			if (rgb565_to_mono_dither(pixel, x, y)) {
				size_t byte_idx = x / 8;
				uint8_t bit_idx = x % 8; /* LSB first */

				row_buf[byte_idx] |= BIT(bit_idx);
			}
		}
		ret = display_write(display_dev, 0, y, &display_row_buf_desc, row_buf);
		if (ret < 0) {
			LOG_ERR("Failed to write to display (error %d)", ret);
			return ret;
		}
	}
	return 0;
}

static int load_background_rgb565(void)
{
	const uint16_t *pixel_data_b16 = (const uint16_t *)current_background->pixel_data;
	uint16_t *row_buf = (uint16_t *)display_row_buf;

	int ret;

	LOG_INF("Loading background for RGB565 display");
	for (size_t y = 0; y < DISPLAY_H; y++) {
		for (size_t x = 0; x < DISPLAY_W; x++) {
			row_buf[x] = (uint16_t)sys_cpu_to_be16(pixel_data_b16[x + y * DISPLAY_W]);
		}
		ret = display_write(display_dev, 0, y, &display_row_buf_desc, row_buf);
		if (ret < 0) {
			LOG_ERR("Failed to write to display (error %d)", ret);
			return ret;
		}
	}
	return 0;
}

static int draw_marker_mono(uint16_t x0, uint16_t y0)
{
	const uint16_t *pixel_data_b16 = (const uint16_t *)current_background->pixel_data;
	uint8_t *marker_buf = marker_draw_buf;
	int ret;

	LOG_DBG("marker center: x0:%d y0:%d", x0, y0);

	/*
	 * Reconstruct a full-width strip from the background and trail. A
	 * full-width pitch is required by monochrome display drivers.
	 */
	memset(marker_buf, 0, marker_draw_buf_desc.buf_size);
	for (size_t y = 0; y < marker_draw_buf_desc.height; y++) {
		for (size_t x = 0; x < marker_draw_buf_desc.width; x++) {
			uint16_t pixel;

			if (canvas_get_pixel_inline(x, y0 + y - marker_draw_buf_desc.height / 2)) {
				pixel = line_color;
			} else {
				pixel = pixel_data_b16[(x) +
						       (y0 + y - marker_draw_buf_desc.height / 2) *
							       DISPLAY_W];
			}

			if (rgb565_to_mono_dither(pixel, x,
						  y0 + y - marker_draw_buf_desc.height / 2)) {
				size_t byte_idx = x / 8;
				uint8_t bit_idx = x % 8; /* LSB first */

				marker_buf[byte_idx + y * (marker_draw_buf_desc.width / 8)] |=
					BIT(bit_idx);
			}
		}
	}

	/* Overlay each rectangular marker segment onto the reconstructed strip. */
	for (size_t i = 0; i < MARKER_DRAW_BUFFER_SEGMENT_ELEMENTS; i++) {
		for (int16_t sy = 0; sy < marker_draw_buffer_segment_dimensions[i].y; sy++) {
			for (int16_t sx = 0; sx < marker_draw_buffer_segment_dimensions[i].x;
			     sx++) {
				if (rgb565_to_mono_dither(
					    marker_color,
					    x0 + sx + marker_draw_buffer_segment_xy[i].x,
					    y0 + sy + marker_draw_buffer_segment_xy[i].y)) {
					int16_t buf_x =
						x0 + sx + marker_draw_buffer_segment_xy[i].x;
					int16_t buf_y =
						y0 + sy + marker_draw_buffer_segment_xy[i].y;

					int16_t bit_x = buf_x;
					int16_t bit_y =
						buf_y - (y0 - marker_draw_buf_desc.height / 2);

					size_t byte_idx = bit_x / 8;
					uint8_t bit_idx = bit_x % 8; /* LSB first */

					marker_buf[byte_idx + bit_y * (marker_draw_buf_desc.width /
								       8)] |= BIT(bit_idx);
				}
			}
		}
	}

	LOG_DBG("write buffer to display: x0:%d y0:%d w:%d h:%d", 0,
		y0 - marker_draw_buf_desc.height / 2, marker_draw_buf_desc.width,
		marker_draw_buf_desc.height);
	ret = display_write(display_dev, 0, y0 - marker_draw_buf_desc.height / 2,
			    &marker_draw_buf_desc, marker_buf);
	if (ret < 0) {
		LOG_ERR("Failed to write to display (error %d)", ret);
		return ret;
	}
	return 0;
}

static int draw_marker_rgb565(uint16_t x0, uint16_t y0)
{
	const uint16_t *pixel_data_b16 = (const uint16_t *)current_background->pixel_data;
	uint16_t *marker_buf = (uint16_t *)marker_draw_buf;
	int ret;

	LOG_DBG("marker center: x0:%d y0:%d", x0, y0);

	/* Reconstruct the marker-sized area from the background and trail. */
	memset(marker_buf, 0, marker_draw_buf_desc.buf_size);
	for (size_t y = 0; y < marker_draw_buf_desc.height; y++) {
		for (size_t x = 0; x < marker_draw_buf_desc.width; x++) {
			uint16_t pixel;

			if (canvas_get_pixel(x0 + x - marker_draw_buf_desc.width / 2,
					     y0 + y - marker_draw_buf_desc.height / 2)) {
				pixel = line_color;
			} else {
				pixel = sys_cpu_to_be16(
					pixel_data_b16[(x0 + x - marker_draw_buf_desc.width / 2) +
						       (y0 + y - marker_draw_buf_desc.height / 2) *
							       DISPLAY_W]);
			}

			marker_buf[x + y * marker_draw_buf_desc.pitch] = pixel;
		}
	}

	/* Overlay each rectangular marker segment at the buffer center. */
	for (size_t i = 0; i < MARKER_DRAW_BUFFER_SEGMENT_ELEMENTS; i++) {
		for (int16_t sy = 0; sy < marker_draw_buffer_segment_dimensions[i].y; sy++) {
			for (int16_t sx = 0; sx < marker_draw_buffer_segment_dimensions[i].x;
			     sx++) {
				marker_buf[(marker_draw_buf_desc.width / 2 + sx +
					    marker_draw_buffer_segment_xy[i].x) +
					   (marker_draw_buf_desc.height / 2 + sy +
					    marker_draw_buffer_segment_xy[i].y) *
						   marker_draw_buf_desc.pitch] = marker_color;
			}
		}
	}

	LOG_DBG("write buffer to display: x0:%d y0:%d w:%d h:%d",
		x0 - marker_draw_buf_desc.width / 2, y0 - marker_draw_buf_desc.height / 2,
		marker_draw_buf_desc.width, marker_draw_buf_desc.height);
	ret = display_write(display_dev, x0 - marker_draw_buf_desc.width / 2,
			    y0 - marker_draw_buf_desc.height / 2, &marker_draw_buf_desc,
			    marker_buf);
	if (ret < 0) {
		LOG_ERR("Failed to write to display (error %d)", ret);
		return ret;
	}
	return 0;
}

enum touch_element app_graphics_marker_touching(uint16_t x0, uint16_t y0)
{
	int16_t x, y;
	const int16_t *pixel_data_b16 = (const int16_t *)current_background->pixel_data;

	for (size_t i = 0; i < MARKER_DRAW_BUFFER_BORDER_ELEMENTS; i++) {
		x = x0 + marker_draw_buffer_border[i].x;
		y = y0 + marker_draw_buffer_border[i].y;

		if (x < 0 || y < 0 || x >= DISPLAY_W || y >= DISPLAY_H) {
			return TOUCH_DISPLAY_BORDER;
		}

		if (sys_cpu_to_be16(pixel_data_b16[y * DISPLAY_W + x]) == finish_color) {
			return TOUCH_FINISH_LINE;
		} else if (sys_cpu_to_be16(pixel_data_b16[y * DISPLAY_W + x]) != bg_color) {
			return TOUCH_WALL;
		}
	}

	return TOUCH_BACKGROUND;
}

int app_graphics_load_background(void)
{
	return load_background_fn();
}

int app_graphics_draw_marker(uint16_t x, uint16_t y)
{
	return draw_marker_fn(x, y);
}
