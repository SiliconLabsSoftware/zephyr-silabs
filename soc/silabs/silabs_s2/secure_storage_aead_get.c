/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Silicon Laboratories Inc.
 */

#include <../library/psa_crypto_driver_wrappers.h>
#include <zephyr/secure_storage/its/transform/aead_get.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/logging/log.h>
#include <psa/crypto.h>
#include <string.h>

LOG_MODULE_DECLARE(secure_storage, CONFIG_SECURE_STORAGE_LOG_LEVEL);

psa_status_t secure_storage_its_transform_aead_get_key(
	secure_storage_its_uid_t uid,
	uint8_t key[static CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_SIZE])
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
	psa_key_lifetime_t builtin_lifetime;
	psa_drv_slot_number_t builtin_slot;

	size_t builtin_key_buffer_length = 0;
	uint8_t builtin_key_buffer[4];
	size_t session_key_length = 0;
	ssize_t hwinfo_ret;
	struct {
		uint8_t device_id[8];
		secure_storage_its_uid_t uid;
	} __packed data;

	/* Use device ID combined with storage uid as IV for key derivation */
	hwinfo_ret = hwinfo_get_device_id(data.device_id, sizeof(data.device_id));
	if (hwinfo_ret < sizeof(data.device_id)) {
		LOG_ERR("Failed to get device ID. (%zd)", hwinfo_ret);
		return PSA_ERROR_HARDWARE_FAILURE;
	}
	data.uid = uid;

	/* Get builtin key attributes */
	psa_set_key_id(&attributes, SL_SE_BUILTIN_KEY_TRUSTZONE_ID);
	status = mbedtls_psa_platform_get_builtin_key(psa_get_key_id(&attributes),
						      &builtin_lifetime, &builtin_slot);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Load builtin key using PSA driver API. Need to use driver wrapper directly since we are
	 * implementing the key storage used by the PSA crypto core, and therefore can't rely on
	 * the regular PSA crypto API.
	 */
	psa_set_key_lifetime(&attributes, builtin_lifetime);
	status = psa_driver_wrapper_get_builtin_key(builtin_slot, &attributes, builtin_key_buffer,
						    sizeof(builtin_key_buffer),
						    &builtin_key_buffer_length);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Derive session key from built-in key using AES-CMAC */
	status = psa_driver_wrapper_mac_compute(
		&attributes, builtin_key_buffer, builtin_key_buffer_length, PSA_ALG_CMAC,
		(const uint8_t *)&data, sizeof(data), key,
		CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_SIZE, &session_key_length);

	/* Verify that key derivation was successful before transferring the key to the caller */
	if (status != PSA_SUCCESS ||
	    session_key_length != CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_SIZE) {
		memset(key, 0, CONFIG_SECURE_STORAGE_ITS_TRANSFORM_AEAD_KEY_SIZE);
		return PSA_ERROR_HARDWARE_FAILURE;
	}

	return status;
}
