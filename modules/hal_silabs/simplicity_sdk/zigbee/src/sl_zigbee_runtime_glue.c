/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr replacement for Simplicity Studio sl_stack_init() and the Zigbee
 * portion of the sl_main process_action loop.
 */

#include <zephyr/autoconf.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "led.h"
#include "sl_status.h"
#include "sl_zigbee_runtime.h"
#include "sl_zigbee_system_common.h"

#if defined(CONFIG_SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE_UPGRADE)
#include "stack/security/zigbee-secure-key-storage-upgrade.h"
#endif

LOG_MODULE_REGISTER(silabs_zigbee_runtime, CONFIG_LOG_DEFAULT_LEVEL);

extern uint32_t sli_zigbee_af_ms_to_next_event(void);

/* sl_stack_init() RAIL util / antenna helpers (see sl_zigbee_stack_platform_glue.c). */
void sl_rail_util_coex_init(void);
void sl_rail_util_pa_init(void);
void sl_rail_util_power_manager_init(void);
sl_status_t sl_rail_util_ant_div_init(void);

static struct k_thread zigbee_thread;
static k_tid_t zigbee_thread_id;
static K_THREAD_STACK_DEFINE(zigbee_thread_stack, CONFIG_SILABS_ZIGBEE_RUNTIME_THREAD_STACK_SIZE);
static bool zigbee_runtime_ready;

static void zigbee_thread_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		sl_zigbee_runtime_process_once();
		k_msleep(sl_zigbee_runtime_ms_until_next_tick());
	}
}

#if !defined(CONFIG_SILABS_SISDK_ZIGBEE_ZCL_CLI)
/*
 * Autogen always references sli_zigbee_zcl_cli_init; provide a no-op until
 * platform sl_cli is ported to Zephyr.
 */
void sli_zigbee_zcl_cli_init(uint8_t init_level)
{
	ARG_UNUSED(init_level);
}
#endif

sl_status_t sl_zigbee_runtime_init(void)
{
	if (zigbee_runtime_ready) {
		return SL_STATUS_OK;
	}

	/*
	 * Match SiSDK autogen sl_stack_init() order from Z3 Light:
	 *   sl_rail_util_coex_init();
	 *   sl_rail_util_pa_init();
	 *   sl_rail_util_power_manager_init();
	 *   sl_rail_util_pti_init();
	 *   sli_zigbee_stack_init_callback();
	 *   sli_zigbee_app_framework_init_callback();
	 *   sli_zigbee_stack_sleep_init();
	 *   sli_zigbee_app_framework_sleep_init();
	 *   sli_zb_sec_man_upgrade_key_storage();
	 *   sl_rail_util_ant_div_init();
	 *
	 * Activity LED is configured here (via Zephyr GPIO) before the stack
	 * can generate TX activity indications.
	 */
	halInternalInitLed();

	sl_rail_util_coex_init();
	sl_rail_util_pa_init();
	sl_rail_util_power_manager_init();
	/* PTI itself is configured by Zephyr's silabs,pti driver when enabled. */
	sli_zigbee_stack_init_callback();
	sli_zigbee_app_framework_init_callback();

	sli_zigbee_stack_sleep_init();
	sli_zigbee_app_framework_sleep_init();

#if defined(CONFIG_SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE_UPGRADE)
	sli_zb_sec_man_upgrade_key_storage();
#endif

	(void)sl_rail_util_ant_div_init();

	zigbee_runtime_ready = true;
	LOG_INF("Zigbee stack and application framework initialized");

	return SL_STATUS_OK;
}

void sl_zigbee_runtime_process_once(void)
{
	sli_zigbee_stack_tick_callback();
	sli_zigbee_app_framework_tick_callback();
}

uint32_t sl_zigbee_runtime_ms_until_next_tick(void)
{
	uint32_t delay_ms = sli_zigbee_af_ms_to_next_event();

	if (delay_ms == 0U) {
		delay_ms = CONFIG_SILABS_ZIGBEE_RUNTIME_DEFAULT_TICK_MS;
	} else if (delay_ms > CONFIG_SILABS_ZIGBEE_RUNTIME_MAX_SLEEP_MS) {
		delay_ms = CONFIG_SILABS_ZIGBEE_RUNTIME_MAX_SLEEP_MS;
	}

	return delay_ms;
}

sl_status_t sl_zigbee_runtime_start(void)
{
	if (zigbee_thread_id != NULL) {
		return SL_STATUS_OK;
	}

	zigbee_thread_id = k_thread_create(&zigbee_thread,
					   zigbee_thread_stack,
					   K_THREAD_STACK_SIZEOF(zigbee_thread_stack),
					   zigbee_thread_entry,
					   NULL, NULL, NULL,
					   CONFIG_SILABS_ZIGBEE_RUNTIME_THREAD_PRIORITY,
					   0,
					   K_NO_WAIT);
	if (zigbee_thread_id == NULL) {
		LOG_ERR("failed to create Zigbee runtime thread");
		return SL_STATUS_FAIL;
	}

	k_thread_name_set(zigbee_thread_id, "zigbee");
	LOG_INF("Zigbee runtime thread started");

	return SL_STATUS_OK;
}
