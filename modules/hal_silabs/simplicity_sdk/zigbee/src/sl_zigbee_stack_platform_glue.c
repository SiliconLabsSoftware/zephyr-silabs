/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Platform glue between the Zigbee prebuilt stack and Zephyr: RAIL util
 * bring-up used by sl_stack_init(), radio scheduler priority table, and
 * legacy HAL helpers referenced at init.
 */

#include <stdint.h>

#include <zephyr/autoconf.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

#include "event_queue/event-queue.h"
#include "hal.h"
#include "stack/internal/inc/multi-network-internal-def.h"
#include "sl_status.h"
#include "stack/include/sl_zigbee_types.h"

#if defined(CONFIG_SOC_GECKO_USE_RAIL)
#include "sl_rail.h"
#endif

uint8_t sl_zigbee_get_current_network(void)
{
	return sli_zigbee_stack_get_current_network();
}

uint8_t sl_zigbee_get_callback_network(void)
{
	return sli_zigbee_stack_get_callback_network();
}

sli_zigbee_event_t *sli_zigbee_get_multi_network_forked_event(sli_zigbee_event_t *list)
{
	return list;
}

uint8_t sli_zigbee_get_network_index_from_multi_network_event(sli_zigbee_event_t *event,
							      sli_zigbee_event_t *list)
{
	ARG_UNUSED(event);
	ARG_UNUSED(list);

	return 0U;
}

sl_802154_radio_priorities_t radioSchedulerPriorityTable = {
	.background_rx = 0U,
	.min_tx_priority = 8U,
	.tx_step = 4U,
	.max_tx_priority = 16U,
	.active_rx = 4U,
};

sl_status_t sli_util_debug_init(void)
{
	return SL_STATUS_OK;
}

void sli_802154phy_radio_seed_random(void)
{
}

void halStackSeedRandom(uint32_t seed)
{
	ARG_UNUSED(seed);
}

void halStackProcessBootCount(void)
{
}

uint16_t halCommonGetInt16uQuarterSecondTick(void)
{
	return (uint16_t)(k_uptime_get_32() / 250U);
}

uint32_t halCommonCrc32(uint8_t newByte, uint32_t prevResult)
{
	uint32_t crc = prevResult;

	for (uint8_t bit = 0U; bit < 8U; bit++) {
		const bool crc_lsb = (crc & 1U) != 0U;
		const bool byte_msb = (newByte & 0x80U) != 0U;

		crc >>= 1U;
		if (crc_lsb ^ byte_msb) {
			crc ^= 0xEDB88320UL;
		}
		newByte <<= 1U;
	}

	return crc;
}

/*
 * sl_stack_init() RAIL util helpers that Zephyr does not already own:
 * - PA: SiSDK pa_conversions (linked with CONFIG_SOC_GECKO_USE_RAIL)
 * - ant_div: SiSDK sl_rail_util_ant_div.c (disabled config = no-op init)
 * - PTI: owned by Zephyr's silabs,pti driver (debug_silabs_pti.c) when &pti
 *   is okay in DTS — do not call RAIL_ConfigPti here
 * - coex: not ported yet
 * - power manager: gated on CONFIG_PM
 */

void sl_rail_util_power_manager_init(void)
{
	/*
	 * SiSDK calls sl_rail_init_power_manager() here. That pulls
	 * sl_power_manager_* symbols; enable once CONFIG_PM + Silabs PM are
	 * wired for Zigbee. Until then keep the sl_stack_init call site.
	 */
#if defined(CONFIG_SOC_GECKO_USE_RAIL) && defined(CONFIG_PM)
	(void)sl_rail_init_power_manager();
#endif
}

bool sl_rail_util_coex_is_enabled(void)
{
	return false;
}

bool sl_rail_util_is_coex_signal_identifier_enabled(void)
{
	return false;
}

typedef uint8_t sl_rail_util_ieee802154_stack_event_t;
typedef uint8_t sl_rail_util_ieee802154_stack_status_t;

sl_rail_util_ieee802154_stack_status_t sl_rail_util_ieee802154_on_event(
	sl_rail_util_ieee802154_stack_event_t stack_event,
	uint32_t supplement)
{
	ARG_UNUSED(stack_event);
	ARG_UNUSED(supplement);

	return 0U;
}
