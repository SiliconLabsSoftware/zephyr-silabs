/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(app_input, LOG_LEVEL_INF);

#include "app_input.h"

#define APP_INPUT_MOUSE_QUEUE_LEN 10

static char input_queue_buffer[APP_INPUT_MOUSE_QUEUE_LEN * sizeof(struct app_input_event)];
static struct k_msgq input_queue;

/* Owned by the mouse producer; flushing from the game never changes these. */
static bool previous_left_button;
static bool previous_right_button;

void app_input_init(void)
{
	k_msgq_init(&input_queue, input_queue_buffer, sizeof(struct app_input_event),
		    APP_INPUT_MOUSE_QUEUE_LEN);
	app_input_reset_mouse();
}

int app_input_submit_mouse(const struct mouse_data_element *mouse_data)
{
	struct app_input_event event;

	if (mouse_data == NULL) {
		return -EINVAL;
	}

	event = (struct app_input_event){
		.dx = mouse_data->dx,
		.dy = mouse_data->dy,
		.left_pressed = mouse_data->left_button && !previous_left_button,
		.right_pressed = mouse_data->right_button && !previous_right_button,
	};
	/* Track every received state even if its queued event is later discarded. */
	previous_left_button = mouse_data->left_button;
	previous_right_button = mouse_data->right_button;

	while (k_msgq_put(&input_queue, &event, K_NO_WAIT) != 0) {
		/*
		 * Preserve the current policy:
		 * if the queue is full, drop old input events and keep the
		 * newest event. Button history survives this purge.
		 */
		k_msgq_purge(&input_queue);
	}

	LOG_DBG("Added new element: x:%d, y:%d, queue load: %d / %d", mouse_data->dx,
		mouse_data->dy, k_msgq_num_used_get(&input_queue), APP_INPUT_MOUSE_QUEUE_LEN);

	return 0;
}

int app_input_get_event(struct app_input_event *event, k_timeout_t timeout)
{
	int ret;

	if (event == NULL) {
		return -EINVAL;
	}

	ret = k_msgq_get(&input_queue, event, timeout);
	if (ret == 0) {
		LOG_DBG("Got element out: x:%d, y:%d, queue load: %d / %d", event->dx, event->dy,
			k_msgq_num_used_get(&input_queue), APP_INPUT_MOUSE_QUEUE_LEN);
	}

	return ret;
}

void app_input_reset_mouse(void)
{
	previous_left_button = false;
	previous_right_button = false;
	app_input_flush();
}

void app_input_flush(void)
{
	k_msgq_purge(&input_queue);
}
