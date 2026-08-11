/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APP_DISPLAY_H_
#define APP_DISPLAY_H_

#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DISPLAY_NODE DT_CHOSEN(zephyr_display)
BUILD_ASSERT(DT_NODE_HAS_STATUS(DISPLAY_NODE, okay), "zephyr,display node is not okay");

#define DISPLAY_W DT_PROP(DISPLAY_NODE, width)
#define DISPLAY_H DT_PROP(DISPLAY_NODE, height)

#ifdef __cplusplus
}
#endif

#endif /* APP_DISPLAY_H_ */
