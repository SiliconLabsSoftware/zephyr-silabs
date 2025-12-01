/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_gecko_trng

#include <zephyr/drivers/entropy.h>
#include <psa/crypto.h>
#include <sli_cryptoacc_driver_trng.h>

static int entropy_cryptoacc_trng_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	return 0;
}

static int entropy_cryptoacc_trng_get_entropy(const struct device *dev,
					      uint8_t *buffer, uint16_t length)
{
	ARG_UNUSED(dev);
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

	status = sli_cryptoacc_trng_get_random(buffer, length);
	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	return 0;
}

/* Entropy driver APIs structure */
static DEVICE_API(entropy, entropy_cryptoacc_trng_api) = {
	.get_entropy = entropy_cryptoacc_trng_get_entropy,
};

/* Entropy driver registration */
DEVICE_DT_INST_DEFINE(0, entropy_cryptoacc_trng_init, NULL, NULL, NULL,
		      PRE_KERNEL_1, CONFIG_ENTROPY_INIT_PRIORITY,
		      &entropy_cryptoacc_trng_api);
