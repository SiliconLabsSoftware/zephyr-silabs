/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "app_led.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(app_led, LOG_LEVEL_INF);

#define LED_NODE DT_ALIAS(led0)

#if !DT_NODE_EXISTS(LED_NODE)
#error "Define devicetree alias led0"
#endif

static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED_NODE, gpios);

struct led_step {
	bool on;
	uint32_t duration_ms;
};

struct led_pattern {
	const struct led_step *steps;
	size_t step_count;
};

/* A zero duration leaves the LED in a steady state. */
static const struct led_step off_pattern[] = {{false, 0}};
static const struct led_step on_pattern[] = {{true, 0}};

static const struct led_step blink_slow_pattern[] = {
	{true, 100},
	{false, 900},
};

static const struct led_step blink_fast_pattern[] = {
	{true, 100},
	{false, 100},
};

static const struct led_step heartbeat_pattern[] = {
	{true, 100},
	{false, 100},
	{true, 100},
	{false, 700},
};

static const struct led_pattern patterns[] = {
	[APP_LED_PATTERN_OFF] = {off_pattern, ARRAY_SIZE(off_pattern)},
	[APP_LED_PATTERN_ON] = {on_pattern, ARRAY_SIZE(on_pattern)},
	[APP_LED_PATTERN_BLINK_SLOW] = {blink_slow_pattern, ARRAY_SIZE(blink_slow_pattern)},
	[APP_LED_PATTERN_BLINK_FAST] = {blink_fast_pattern, ARRAY_SIZE(blink_fast_pattern)},
	[APP_LED_PATTERN_HEARTBEAT] = {heartbeat_pattern, ARRAY_SIZE(heartbeat_pattern)},
};

static struct k_work_delayable led_work;
static struct k_work pattern_work;
static struct k_spinlock led_lock;

/* Shared request state, protected by led_lock. */
static enum app_led_pattern requested_pattern;
static bool change_pending;
static bool initialized;

/* Both work items run on the system workqueue and exclusively own playback. */
static const struct led_pattern *active_pattern;
static size_t active_step;

static void led_advance_step(void)
{
	const struct led_step *step = &active_pattern->steps[active_step];
	int ret;

	ret = gpio_pin_set_dt(&led, step->on);
	if (ret) {
		LOG_ERR("Failed to set LED: %d", ret);
		return;
	}

	active_step = (active_step + 1) % active_pattern->step_count;
	if (step->duration_ms != 0) {
		(void)k_work_schedule(&led_work, K_MSEC(step->duration_ms));
	}
}

static void led_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	led_advance_step();
}

static void pattern_work_handler(struct k_work *work)
{
	enum app_led_pattern pattern;
	k_spinlock_key_t key;

	ARG_UNUSED(work);

	/* A redundant submission must not restart a pattern already applied. */
	key = k_spin_lock(&led_lock);
	if (!change_pending) {
		k_spin_unlock(&led_lock, key);
		return;
	}
	pattern = requested_pattern;
	change_pending = false;
	k_spin_unlock(&led_lock, key);

	/* Same queue: led_work cannot be running while this handler executes. */
	(void)k_work_cancel_delayable(&led_work);
	active_pattern = &patterns[pattern];
	active_step = 0;
	led_advance_step();
}

int app_led_init(void)
{
	int ret;
	k_spinlock_key_t key;

	if (!gpio_is_ready_dt(&led)) {
		return -ENODEV;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_INACTIVE);
	if (ret) {
		return ret;
	}

	k_work_init_delayable(&led_work, led_work_handler);
	k_work_init(&pattern_work, pattern_work_handler);

	active_pattern = &patterns[APP_LED_PATTERN_OFF];
	active_step = 0;
	key = k_spin_lock(&led_lock);
	requested_pattern = APP_LED_PATTERN_OFF;
	change_pending = false;
	initialized = true;
	k_spin_unlock(&led_lock, key);

	return 0;
}

int app_led_set_pattern(enum app_led_pattern pattern)
{
	k_spinlock_key_t key;
	int ret;

	if ((unsigned int)pattern >= ARRAY_SIZE(patterns)) {
		return -EINVAL;
	}

	key = k_spin_lock(&led_lock);
	if (!initialized) {
		k_spin_unlock(&led_lock, key);
		return -EAGAIN;
	}

	requested_pattern = pattern;
	change_pending = true;
	k_spin_unlock(&led_lock, key);

	ret = k_work_submit(&pattern_work);
	return ret < 0 ? ret : 0;
}
