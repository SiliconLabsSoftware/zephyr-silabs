/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

static void *psa_crypto_setup(void)
{
	return NULL;
}

ZTEST_SUITE(psa_crypto_test, NULL, psa_crypto_setup, NULL, NULL, NULL);
