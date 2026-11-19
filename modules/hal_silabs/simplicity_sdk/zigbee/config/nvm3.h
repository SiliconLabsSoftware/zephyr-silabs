/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Minimal NVM3 key helpers for Zigbee CTM token code on Zephyr.
 * Stock sl_zigbee_token.c includes nvm3.h only for NVM3_KEY_MASK.
 */

#ifndef NVM3_H
#define NVM3_H

#ifdef __cplusplus
extern "C" {
#endif

#define NVM3_KEY_SIZE 20U
#define NVM3_KEY_MASK ((1U << NVM3_KEY_SIZE) - 1U)

#ifdef __cplusplus
}
#endif

#endif /* NVM3_H */
