/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal legacy HAL implementations required by Zigbee stack init and tick.
 */

#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

#include "hal.h"
#include "led.h"
#include "micro.h"

#if DT_NODE_HAS_STATUS(DT_ALIAS(led0), okay)
#define ZIGBEE_ACTIVITY_LED_NODE DT_ALIAS(led0)
#endif

void halResetWatchdog(void)
{
}

uint16_t halCommonGetInt16uMillisecondTick(void)
{
	return (uint16_t)k_uptime_get_32();
}

uint32_t halCommonGetInt32uMillisecondTick(void)
{
	return k_uptime_get_32();
}

uint16_t halCommonGetRandom(void)
{
	return (uint16_t)(sys_rand32_get() & 0xFFFFU);
}

bool halInternalWatchDogEnabled(void)
{
	return false;
}

void halInternalDisableWatchDog(uint8_t magicKey)
{
	ARG_UNUSED(magicKey);
}

void halInternalEnableWatchDog(void)
{
}

uint8_t halGetResetInfo(void)
{
	return 0U;
}

const char *halGetResetString(void)
{
	return "UNKNOWN";
}

uint16_t halGetExtendedResetInfo(void)
{
	return 0U;
}

const char *halGetExtendedResetString(void)
{
	return "";
}

#if defined(ZIGBEE_ACTIVITY_LED_NODE)
static const struct gpio_dt_spec activity_led =
	GPIO_DT_SPEC_GET(ZIGBEE_ACTIVITY_LED_NODE, gpios);
static bool activity_led_ready;

void halInternalInitLed(void)
{
	if (activity_led_ready) {
		return;
	}

	if (!gpio_is_ready_dt(&activity_led)) {
		return;
	}

	if (gpio_pin_configure_dt(&activity_led, GPIO_OUTPUT_INACTIVE) != 0) {
		return;
	}

	activity_led_ready = true;
}

void halStackIndicateActivity(bool turnOn)
{
	/*
	 * Called from the MAC TX path with interrupts disabled; keep this a
	 * direct GPIO write (matches SiSDK BOARD_ACTIVITY_LED behavior).
	 */
	if (activity_led_ready) {
		(void)gpio_pin_set_dt(&activity_led, turnOn ? 1 : 0);
	}
}
#else
void halInternalInitLed(void)
{
}

void halStackIndicateActivity(bool turnOn)
{
	ARG_UNUSED(turnOn);
}
#endif
