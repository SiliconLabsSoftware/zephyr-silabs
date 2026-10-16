/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr replacement for Silabs NVM3 ITS key-id rename used by
 * sl_sec_man_copy_key() when MBEDTLS_PSA_CRYPTO_STORAGE_C is enabled.
 * Uses export/destroy/import so it works with Zephyr secure_storage ITS.
 */

#include <string.h>

#include <zephyr/sys/util.h>

#include "psa/crypto.h"

#define SLI_PSA_ITS_CHANGE_KEY_MAX_BYTES 64

psa_status_t sli_psa_its_change_key_id(mbedtls_svc_key_id_t old_id,
				       mbedtls_svc_key_id_t new_id)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	uint8_t key_buf[SLI_PSA_ITS_CHANGE_KEY_MAX_BYTES];
	size_t key_len = 0;
	psa_key_id_t imported_id = new_id;

	if (mbedtls_svc_key_id_equal(old_id, new_id)) {
		return PSA_SUCCESS;
	}

	status = psa_get_key_attributes(old_id, &attributes);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_export_key(old_id, key_buf, sizeof(key_buf), &key_len);
	if (status != PSA_SUCCESS) {
		psa_reset_key_attributes(&attributes);
		return status;
	}

	(void)psa_destroy_key(old_id);

	psa_set_key_id(&attributes, new_id);
	status = psa_import_key(&attributes, key_buf, key_len, &imported_id);
	psa_reset_key_attributes(&attributes);
	memset(key_buf, 0, sizeof(key_buf));

	return status;
}
