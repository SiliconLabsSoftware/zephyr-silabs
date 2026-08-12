/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Z3 Light application callbacks (SiSDK app.c), with Zephyr GPIO for LED/button.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/devicetree.h>
#include <zephyr/logging/log.h>

#include "app/framework/include/af.h"
#ifdef SL_COMPONENT_CATALOG_PRESENT
#include "sl_component_catalog.h"
#endif

#include "network-creator.h"
#include "network-creator-security.h"
#include "network-steering.h"
#include "find-and-bind-target.h"

#ifdef SL_CATALOG_ZIGBEE_ZLL_COMMISSIONING_COMMON_PRESENT
#include "zll-commissioning.h"
#endif //SL_CATALOG_ZIGBEE_ZLL_COMMISSIONING_COMMON_PRESENT

LOG_MODULE_REGISTER(zigbee_z3_light_app, CONFIG_LOG_DEFAULT_LEVEL);

#define LED_BLINK_PERIOD_MS     2000
#define LIGHT_ENDPOINT          1
#define ZIGBEE_STARTUP_DELAY_MS 40

#if DT_NODE_HAS_STATUS(DT_ALIAS(led0), okay)
static const struct gpio_dt_spec app_led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);

static void led_turn_on(void)
{
	(void)gpio_pin_set_dt(&app_led, 1);
}

static void led_turn_off(void)
{
	(void)gpio_pin_set_dt(&app_led, 0);
}

static void led_toggle(void)
{
	(void)gpio_pin_toggle_dt(&app_led);
}
#else
static void led_turn_on(void)
{
}

static void led_turn_off(void)
{
}

static void led_toggle(void)
{
}
#endif

static sl_zigbee_af_event_t commissioning_led_event;
static sl_zigbee_af_event_t finding_and_binding_event;

#if DT_NODE_HAS_STATUS(DT_ALIAS(sw0), okay)
static const struct gpio_dt_spec app_btn = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);
static struct gpio_callback app_btn_cb;

static void app_btn_isr(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);

	/* Released (inactive) → start find-and-bind, same as SiSDK button path. */
	sl_zigbee_af_event_set_active(&finding_and_binding_event);
}
#endif

static void app_gpio_init(void)
{
#if DT_NODE_HAS_STATUS(DT_ALIAS(led0), okay)
	if (!gpio_is_ready_dt(&app_led)) {
		LOG_ERR("LED GPIO device not ready");
	} else if (gpio_pin_configure_dt(&app_led, GPIO_OUTPUT_INACTIVE) != 0) {
		LOG_ERR("failed to configure LED GPIO");
	}
#endif

#if DT_NODE_HAS_STATUS(DT_ALIAS(sw0), okay)
	if (!gpio_is_ready_dt(&app_btn)) {
		LOG_ERR("button GPIO device not ready");
		return;
	}

	if (gpio_pin_configure_dt(&app_btn, GPIO_INPUT) != 0) {
		LOG_ERR("failed to configure button GPIO");
		return;
	}

	if (gpio_pin_interrupt_configure_dt(&app_btn, GPIO_INT_EDGE_TO_INACTIVE) != 0) {
		LOG_ERR("failed to configure button interrupt");
		return;
	}

	gpio_init_callback(&app_btn_cb, app_btn_isr, BIT(app_btn.pin));
	gpio_add_callback(app_btn.port, &app_btn_cb);
#endif
}

static void commissioning_led_event_handler(sl_zigbee_af_event_t *event)
{
	(void)event;

	if (sl_zigbee_af_network_state() == SL_ZIGBEE_JOINED_NETWORK) {
		uint16_t identifyTime;

		sl_zigbee_af_read_server_attribute(LIGHT_ENDPOINT,
						   ZCL_IDENTIFY_CLUSTER_ID,
						   ZCL_IDENTIFY_TIME_ATTRIBUTE_ID,
						   (uint8_t *)&identifyTime,
						   sizeof(identifyTime));
		if (identifyTime > 0) {
			led_toggle();
			sl_zigbee_af_event_set_delay_ms(&commissioning_led_event,
							LED_BLINK_PERIOD_MS << 1);
		} else {
			led_turn_on();
		}
	} else {
		sl_zigbee_af_network_steering_autostart();
	}
}

static void finding_and_binding_event_handler(sl_zigbee_af_event_t *event)
{
	(void)event;

	if (sl_zigbee_af_network_state() == SL_ZIGBEE_JOINED_NETWORK) {
		sl_zigbee_af_event_set_inactive(&finding_and_binding_event);
		LOG_INF("Find and bind target start: 0x%02X",
			sl_zigbee_af_find_and_bind_target_start(LIGHT_ENDPOINT));
	}
}

//----------------------
// Implemented Callbacks

/** @brief Stack Status
 *
 * This function is called by the application framework from the stack status
 * handler.  This callbacks provides applications an opportunity to be notified
 * of changes to the stack status and take appropriate action. The framework
 * will always process the stack status after the callback returns.
 */
void sl_zigbee_af_stack_status_cb(sl_status_t status)
{
	if (status == SL_STATUS_NETWORK_DOWN) {
		led_turn_off();
	} else if (status == SL_STATUS_NETWORK_UP) {
		led_turn_on();
		sl_zigbee_af_event_set_active(&finding_and_binding_event);
	}
}

/** @brief Init
 * Application init function
 */
void sl_zigbee_af_main_init_cb(void)
{
	app_gpio_init();

	sl_zigbee_af_event_init(&commissioning_led_event, commissioning_led_event_handler);
	sl_zigbee_af_isr_event_init(&finding_and_binding_event, finding_and_binding_event_handler);

  // Start the commissioning LED event after network is up, and communicated to app framework task in the main loop
  sl_zigbee_af_event_set_delay_ms(&commissioning_led_event, ZIGBEE_STARTUP_DELAY_MS);
}

/** @brief Complete network steering.
 *
 * This callback is fired when the Network Steering plugin is complete.
 *
 * @param status On success this will be set to SL_STATUS_OK to indicate a
 * network was joined successfully. On failure this will be the status code of
 * the last join or scan attempt.
 *
 * @param totalBeacons The total number of 802.15.4 beacons that were heard,
 * including beacons from different devices with the same PAN ID.
 *
 * @param joinAttempts The number of join attempts that were made to get onto
 * an open Zigbee network.
 *
 * @param finalState The finishing state of the network steering process. From
 * this, one is able to tell on which channel mask and with which key the
 * process was complete.
 */
void sl_zigbee_af_network_steering_complete_cb(sl_status_t status,
                                               uint8_t totalBeacons,
                                               uint8_t joinAttempts,
                                               uint8_t finalState)
{
	(void)totalBeacons;
	(void)joinAttempts;
	(void)finalState;

	LOG_INF("Join network complete: 0x%02X", status);

	if (status != SL_STATUS_OK) {
#ifdef SL_CATALOG_ZIGBEE_ZLL_COMMISSIONING_COMMON_PRESENT
		status = sl_zigbee_af_zll_set_initial_security_state();
		if (status != SL_STATUS_OK) {
			LOG_ERR("cannot initialize ZLL security: 0x%02X", status);
		}
#endif
		status = sl_zigbee_af_network_creator_start(false); /* distributed */
		LOG_INF("Form network start: 0x%02X", status);
	}
}

/** @brief Complete the network creation process.
 *
 * This callback notifies the user that the network creation process has
 * completed successfully.
 *
 * @param network The network that the network creator plugin successfully
 * formed.
 *
 * @param usedSecondaryChannels Whether or not the network creator wants to
 * form a network on the secondary channels.
 */
void sl_zigbee_af_network_creator_complete_cb(const sl_zigbee_network_parameters_t *network,
					      bool usedSecondaryChannels)
{
	(void)network;
	(void)usedSecondaryChannels;

	LOG_INF("Form Network Complete");
}

/** @brief Post Attribute Change
 *
 * This function is called by the application framework after it changes an
 * attribute value. The value passed into this callback is the value to which
 * the attribute was set by the framework.
 */
void sl_zigbee_af_post_attribute_change_cb(uint8_t endpoint,
                                           sl_zigbee_af_cluster_id_t clusterId,
                                           sl_zigbee_af_attribute_id_t attributeId,
                                           uint8_t mask,
                                           uint16_t manufacturerCode,
                                           uint8_t type,
                                           uint8_t size,
                                           uint8_t* value)
{
	(void)manufacturerCode;
	(void)type;
	(void)size;
	(void)value;

	if (clusterId == ZCL_ON_OFF_CLUSTER_ID && attributeId == ZCL_ON_OFF_ATTRIBUTE_ID &&
	    mask == CLUSTER_MASK_SERVER) {
		bool onOff;

		if (sl_zigbee_af_read_server_attribute(endpoint, ZCL_ON_OFF_CLUSTER_ID,
						       ZCL_ON_OFF_ATTRIBUTE_ID, (uint8_t *)&onOff,
						       sizeof(onOff)) ==
		    SL_ZIGBEE_ZCL_STATUS_SUCCESS) {
			if (onOff) {
				led_turn_on();
			} else {
				led_turn_off();
			}
		}
	}
}

/** @brief On/off Cluster Server Post Init
 *
 * Following resolution of the On/Off state at startup for this endpoint, perform any
 * additional initialization needed; e.g., synchronize hardware state.
 *
 * @param endpoint Endpoint that is being initialized
 */
void sl_zigbee_af_on_off_cluster_server_post_init_cb(uint8_t endpoint)
{
  // At startup, trigger a read of the attribute and possibly a toggle of the
  // LED to make sure they are always in sync.
  sl_zigbee_af_post_attribute_change_cb(endpoint,
                                        ZCL_ON_OFF_CLUSTER_ID,
                                        ZCL_ON_OFF_ATTRIBUTE_ID,
                                        CLUSTER_MASK_SERVER,
                                        0,
                                        0,
                                        0,
                                        NULL);
}

/** @brief
 *
 * Application framework equivalent of ::sl_zigbee_radio_needs_calibrating_handler
 */
void sl_zigbee_af_radio_needs_calibrating_cb(void)
{
#ifndef EZSP_HOST
	sl_mac_calibrate_current_channel();
#endif
}
