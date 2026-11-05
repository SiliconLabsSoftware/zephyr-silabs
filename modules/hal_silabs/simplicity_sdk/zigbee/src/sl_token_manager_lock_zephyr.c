/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr substitute for sl_token_manager_lock.c (CMSIS-OS / CORE_CRITICAL).
 * Matches the CTM lock API that stock sl_token_manager_api.c uses around
 * static token access (and init).
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>

#include "sl_token_manager_lock.h"

static struct k_mutex ctm_mutex;
static bool ctm_mutex_ready;

static int ctm_lock_sys_init(void)
{
	k_mutex_init(&ctm_mutex);
	ctm_mutex_ready = true;
	return 0;
}

SYS_INIT(ctm_lock_sys_init, POST_KERNEL, 0);

void sl_token_manager_lock_create_mutex(void)
{
	if (!ctm_mutex_ready) {
		k_mutex_init(&ctm_mutex);
		ctm_mutex_ready = true;
	}
}

void sl_token_manager_lock_begin(void)
{
	if (!ctm_mutex_ready) {
		sl_token_manager_lock_create_mutex();
	}

	k_mutex_lock(&ctm_mutex, K_FOREVER);
}

void sl_token_manager_lock_end(void)
{
	k_mutex_unlock(&ctm_mutex);
}
