/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

static const uint8_t client_private_key[] = {
	0xB0, 0x76, 0x51, 0xEA, 0x20, 0xF0, 0x28, 0xA8, 0x16, 0xEE, 0x01,
	0xB0, 0xD1, 0x06, 0x2A, 0x7C, 0x81, 0x58, 0xE8, 0x84, 0xE9, 0xBC,
	0xC6, 0x1C, 0x5D, 0xAB, 0xDB, 0x4E, 0x38, 0x2F, 0x96, 0x69,
};
static const uint8_t client_public_key[] = {
	0x87, 0xD8, 0x6B, 0xDA, 0xAC, 0x38, 0x3C, 0x85, 0xA6, 0xBC, 0xF8,
	0xFC, 0xC6, 0x26, 0xD6, 0x14, 0x36, 0xE4, 0x8F, 0xDB, 0xFA, 0x5A,
	0x45, 0xFE, 0x0C, 0x9E, 0xA8, 0x4B, 0x35, 0x3E, 0xF1, 0x37,
};
static const uint8_t server_private_key[] = {
	0x98, 0x2E, 0xB6, 0x7D, 0x0A, 0x01, 0x57, 0x90, 0xE1, 0x45, 0xF3,
	0x67, 0xF6, 0xDA, 0xA6, 0x44, 0x2C, 0x87, 0xC0, 0xED, 0x3C, 0x36,
	0x71, 0xA6, 0x89, 0xC7, 0x49, 0xAC, 0x0D, 0xFE, 0x43, 0x6E,
};
static const uint8_t server_public_key[] = {
	0x0C, 0x04, 0x10, 0x5B, 0xE8, 0x7C, 0xAB, 0x37, 0x21, 0x15, 0x7A,
	0x8D, 0x49, 0x85, 0x8C, 0x7A, 0x9F, 0xC1, 0x46, 0xDA, 0xCC, 0x96,
	0xEF, 0x6E, 0xD4, 0xDA, 0x71, 0xBF, 0xED, 0x32, 0x0D, 0x76,
};
static const uint8_t expected_shared_secret[] = {
	0xF2, 0xE6, 0x0E, 0x1C, 0xB7, 0x64, 0xBC, 0x48, 0xF2, 0x9D, 0xBB,
	0x12, 0xFB, 0x12, 0x17, 0x31, 0x32, 0x1D, 0x79, 0xAF, 0x0A, 0x9F,
	0xAB, 0xAD, 0x34, 0x05, 0xA2, 0x07, 0x39, 0x9C, 0x5F, 0x15,
};

ZTEST(psa_crypto_test, test_key_agreement_ecdh_25519)
{
	uint8_t shared_secret_buf[32];
	size_t shared_secret_len;
	psa_key_id_t key_id;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Import client key */
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	if (IS_ENABLED(TEST_WRAPPED_KEYS)) {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
							  PSA_KEY_PERSISTENCE_VOLATILE, 1));
	}
	zassert_equal(psa_import_key(&attributes, client_private_key, sizeof(client_private_key),
				     &key_id),
		      PSA_SUCCESS, "Failed to import client key");

	/* Perform key agreement with server public key */
	zassert_equal(psa_raw_key_agreement(PSA_ALG_ECDH, key_id, server_public_key,
					    sizeof(server_public_key), shared_secret_buf,
					    sizeof(shared_secret_buf), &shared_secret_len),
		      PSA_SUCCESS, "Failed to perform key agreement with server");
	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy client key");

	/* Import server key */
	attributes = psa_key_attributes_init();
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	if (IS_ENABLED(TEST_WRAPPED_KEYS)) {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
							  PSA_KEY_PERSISTENCE_VOLATILE, 1));
	}
	zassert_equal(psa_import_key(&attributes, server_private_key, sizeof(server_private_key),
				     &key_id),
		      PSA_SUCCESS, "Failed to import server key");

	/* Perform key agreement with client public key */
	zassert_equal(psa_raw_key_agreement(PSA_ALG_ECDH, key_id, client_public_key,
					    sizeof(client_public_key), shared_secret_buf,
					    sizeof(shared_secret_buf), &shared_secret_len),
		      PSA_SUCCESS, "Failed to perform key agreement with client");
	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy server key");

	/* Verify shared secret */
	zassert_mem_equal(shared_secret_buf, expected_shared_secret, sizeof(expected_shared_secret),
			  "Key agreement did not resolve the correct shared secret");
}
