/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr Kconfig to Silicon Labs Zigbee configuration mapping.
 * Extend this header as Zigbee SDK sources and runtime glue are integrated.
 */

#ifndef SL_ZIGBEE_CONFIG_H
#define SL_ZIGBEE_CONFIG_H

#include "sl_component_catalog.h"

/* SL_RAIL_IEEE802154_CCA_MODE_RSSI; avoid pulling RAIL headers at compile time. */
#ifndef SL_ZIGBEE_RADIO_802154_CCA_MODE
#define SL_ZIGBEE_RADIO_802154_CCA_MODE 0
#endif

/*
 * AF provides endpoint accessors in af-soc.c. Suppress the stack stubs in
 * sl_zigbee_endpoint_stubs.c, which would otherwise duplicate those symbols.
 */
#if defined(CONFIG_SILABS_SISDK_ZIGBEE_ZCL_FRAMEWORK_CORE) && \
	CONFIG_SILABS_SISDK_ZIGBEE_ZCL_FRAMEWORK_CORE
#define SL_ZIGBEE_APPLICATION_HAS_GET_ENDPOINT
#endif

#endif /* SL_ZIGBEE_CONFIG_H */
