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
#include <zephyr/sys/util.h>

#define LED_NODE DT_ALIAS(led0)

#if !DT_NODE_EXISTS(LED_NODE)
#error "Define devicetree alias led0"
#endif

static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED_NODE, gpios);

struct led_step {
	bool on;
	uint32_t duration_ms;
};

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

static struct k_work_delayable led_work;

static const struct led_step *active_pattern;
static size_t active_pattern_len;
static size_t active_step;

static void led_work_handler(struct k_work *work)
{
	const struct led_step *step;

	ARG_UNUSED(work);

	if (active_pattern == NULL || active_pattern_len == 0) {
		return;
	}

	step = &active_pattern[active_step];

	gpio_pin_set_dt(&led, step->on);

	active_step++;
	if (active_step >= active_pattern_len) {
		active_step = 0;
	}

	k_work_schedule(&led_work, K_MSEC(step->duration_ms));
}

static int led_pattern_start(const struct led_step *pattern, size_t pattern_len)
{
	if (pattern == NULL || pattern_len == 0) {
		return -EINVAL;
	}

	k_work_cancel_delayable(&led_work);

	active_pattern = pattern;
	active_pattern_len = pattern_len;
	active_step = 0;

	k_work_schedule(&led_work, K_NO_WAIT);

	return 0;
}

static void led_pattern_stop(void)
{
	k_work_cancel_delayable(&led_work);

	active_pattern = NULL;
	active_pattern_len = 0;
	active_step = 0;
}

int app_led_init(void)
{
	int ret;

	if (!gpio_is_ready_dt(&led)) {
		return -ENODEV;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_INACTIVE);
	if (ret) {
		return ret;
	}

	k_work_init_delayable(&led_work, led_work_handler);

	active_pattern = NULL;
	active_pattern_len = 0;
	active_step = 0;

	return 0;
}

int app_led_on(void)
{
	led_pattern_stop();
	return gpio_pin_set_dt(&led, 1);
}

int app_led_off(void)
{
	led_pattern_stop();
	return gpio_pin_set_dt(&led, 0);
}

int app_led_blink_slow(void)
{
	return led_pattern_start(blink_slow_pattern, ARRAY_SIZE(blink_slow_pattern));
}

int app_led_blink_fast(void)
{
	return led_pattern_start(blink_fast_pattern, ARRAY_SIZE(blink_fast_pattern));
}

int app_led_heartbeat(void)
{
	return led_pattern_start(heartbeat_pattern, ARRAY_SIZE(heartbeat_pattern));
}
