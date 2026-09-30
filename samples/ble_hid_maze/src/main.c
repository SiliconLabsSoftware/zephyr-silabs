/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 * Copyright (c) 2019 Jan Van Winkel <jan.van_winkel@dxplore.eu>
 *
 * Based on ST7789V sample:
 * Copyright (c) 2019 Marc Reilly
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <stdint.h>
#include <stdlib.h>

#include "app_types.h"
#include "ble_hid_app.h"
#include "app_input.h"
#include "app_display.h"
#include "app_graphics.h"
#include "app_graphics_marker.h"

enum states_t {
	APP_STATE_START,
	APP_STATE_LOAD_GAME,
	APP_STATE_RUN_GAME,
	APP_STATE_FINISH_GAME,
};

enum move_result {
	MOVE_ADVANCED,
	MOVE_BLOCKED,
	MOVE_FINISHED,
};

struct line_state {
	int16_t x;
	int16_t y;
	int16_t target_x;
	int16_t target_y;
	int16_t dx;
	int16_t dy;
	int16_t sx;
	int16_t sy;
	int16_t err;
};

static enum move_result slide_along_wall(struct line_state *line, int16_t old_err)
{
	bool can_move_x = false;
	bool can_move_y = false;
	enum touch_element touched_x = TOUCH_WALL;
	enum touch_element touched_y = TOUCH_WALL;
	bool prefer_x;
	bool move_x;

	if (line->x != line->target_x) {
		touched_x = app_graphics_marker_touching(line->x + line->sx, line->y);
		can_move_x = touched_x != TOUCH_WALL;
	}

	if (line->y != line->target_y) {
		touched_y = app_graphics_marker_touching(line->x, line->y + line->sy);
		can_move_y = touched_y != TOUCH_WALL;
	}

	/*
	 * Check the finish line for the alternative movements too.
	 */
	if ((can_move_x && touched_x == TOUCH_FINISH_LINE) ||
	    (can_move_y && touched_y == TOUCH_FINISH_LINE)) {
		return MOVE_FINISHED;
	}

	/*
	 * Prefer the axis having the largest remaining mouse movement. If it is
	 * blocked, slide along the other axis.
	 */
	prefer_x = abs(line->target_x - line->x) >= abs(line->target_y - line->y);
	move_x = can_move_x && (prefer_x || !can_move_y);

	if (move_x) {
		line->x += line->sx;
		line->err = old_err - line->dy;
		return MOVE_ADVANCED;
	}

	if (can_move_y) {
		line->y += line->sy;
		line->err = old_err + line->dx;
		return MOVE_ADVANCED;
	}

	LOG_DBG("Draw completely blocked");
	line->target_x = line->x;
	line->target_y = line->y;
	return MOVE_BLOCKED;
}

static enum move_result move_one_step(struct line_state *line)
{
	int16_t old_err = line->err;
	int16_t e2 = 2 * old_err;
	bool step_x = (line->x != line->target_x) && (e2 > -line->dy);
	bool step_y = (line->y != line->target_y) && (e2 < line->dx);
	int16_t next_x = line->x + (step_x ? line->sx : 0);
	int16_t next_y = line->y + (step_y ? line->sy : 0);
	int16_t next_err = old_err;
	enum touch_element touched;

	if (step_x) {
		next_err -= line->dy;
	}

	if (step_y) {
		next_err += line->dx;
	}

	touched = app_graphics_marker_touching(next_x, next_y);
	if (touched == TOUCH_FINISH_LINE) {
		return MOVE_FINISHED;
	}

	if (touched == TOUCH_WALL) {
		return slide_along_wall(line, old_err);
	}

	line->x = next_x;
	line->y = next_y;
	line->err = next_err;
	return MOVE_ADVANCED;
}

static int move_marker(struct int16_xy_pair *marker_pos_actual,
		       const struct int16_xy_pair *marker_pos_new, bool *finished)
{
	struct line_state line = {
		.x = marker_pos_actual->x,
		.y = marker_pos_actual->y,
		.target_x = marker_pos_new->x,
		.target_y = marker_pos_new->y,
	};
	uint8_t draw_step = 0;
	int ret;

	line.dx = abs(line.target_x - line.x);
	line.dy = abs(line.target_y - line.y);
	line.sx = (line.x < line.target_x) ? 1 : -1;
	line.sy = (line.y < line.target_y) ? 1 : -1;
	line.err = line.dx - line.dy;

	while (line.x != line.target_x || line.y != line.target_y) {
		enum move_result result = move_one_step(&line);

		if (result == MOVE_FINISHED) {
			LOG_INF("Drawing: touched finish color");
			*finished = true;
			return 0;
		}

		app_graphics_canvas_draw(line.x, line.y);

		/*
		 * Keep the logical position synchronized with every collision-free
		 * step. Display updates can still be throttled.
		 */
		marker_pos_actual->x = line.x;
		marker_pos_actual->y = line.y;
		draw_step++;

		/*
		 * A wall can stop the Bresenham loop before the next throttled display
		 * update. In that case render the final position as well.
		 */
		if (draw_step < MAX_MOVEMENT_WITHOUT_UPDATE &&
		    (line.x != line.target_x || line.y != line.target_y)) {
			continue;
		}

		ret = app_graphics_draw_marker(line.x, line.y);
		if (ret) {
			LOG_ERR("Draw marker failed: %d", ret);
			return ret;
		}
		draw_step = 0;
	}

	return 0;
}

static int run_game(struct int16_xy_pair *marker_pos_actual, enum states_t *app_state)
{
	struct mouse_data_element mouse_data;
	struct int16_xy_pair marker_pos_new;
	bool finished = false;
	int ret;

	ret = app_input_get_mouse(&mouse_data, K_FOREVER);
	if (ret) {
		return 0;
	}

	if (mouse_data.left_button) {
		*app_state = APP_STATE_LOAD_GAME;
		return 0;
	}

	if (mouse_data.right_button) {
		*app_state = APP_STATE_LOAD_GAME;
		app_graphics_next_background();
		return 0;
	}

	marker_pos_new.x = CLAMP((int32_t)marker_pos_actual->x + mouse_data.dx,
				 MARKER_BUF_DIM / 2 + 1, DISPLAY_W - MARKER_BUF_DIM / 2 - 1);
	marker_pos_new.y = CLAMP((int32_t)marker_pos_actual->y + mouse_data.dy,
				 MARKER_BUF_DIM / 2 + 1, DISPLAY_H - MARKER_BUF_DIM / 2 - 1);

	ret = move_marker(marker_pos_actual, &marker_pos_new, &finished);
	if (finished) {
		*app_state = APP_STATE_FINISH_GAME;
	}

	return ret;
}

int main(void)
{
	enum states_t app_state = APP_STATE_START;
	struct int16_xy_pair marker_pos_actual;
	int ret;

	while (true) {
		switch (app_state) {
		case APP_STATE_START:
			LOG_INF("Starting BLE Maze game");

			app_input_init();
			ret = app_graphics_init();
			if (ret) {
				LOG_ERR("App graphics init failed: %d", ret);
				return ret;
			}

			ret = ble_hid_app_start();
			if (ret) {
				LOG_ERR("HID app start failed: %d", ret);
				return ret;
			}

			app_state = APP_STATE_LOAD_GAME;
			break;

		case APP_STATE_LOAD_GAME:
			app_graphics_canvas_clear();
			ret = app_graphics_load_background();
			if (ret) {
				LOG_ERR("Load background failed: %d", ret);
				return ret;
			}

			marker_pos_actual.x = 10;
			marker_pos_actual.y = DISPLAY_H / 2;
			app_graphics_canvas_draw(marker_pos_actual.x, marker_pos_actual.y);
			ret = app_graphics_draw_marker(marker_pos_actual.x, marker_pos_actual.y);
			if (ret) {
				LOG_ERR("Draw marker failed: %d", ret);
				return ret;
			}

			app_input_flush();

			app_state = APP_STATE_RUN_GAME;
			break;

		case APP_STATE_RUN_GAME:
			ret = run_game(&marker_pos_actual, &app_state);
			if (ret) {
				return ret;
			}
			break;

		case APP_STATE_FINISH_GAME:

			LOG_INF("Game: loading the next background");

			k_msleep(500);

			app_graphics_next_background();

			app_state = APP_STATE_LOAD_GAME;
			break;

		default:
			app_state = APP_STATE_START;
			break;
		}
	}
}
