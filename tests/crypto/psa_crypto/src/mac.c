/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

#include "test_vectors.h"

static uint8_t key[32] = {
	0x99, 0x1a, 0xbd, 0x17, 0x1c, 0x3e, 0x55, 0x1b, 0xed, 0x7a, 0xd9,
	0xae, 0x8f, 0x97, 0x23, 0xca, 0xc0, 0x38, 0x2a, 0x3d, 0xbb, 0x77,
	0x17, 0xea, 0x4a, 0x62, 0xb2, 0x5b, 0x89, 0x15, 0x15, 0xab,
};

static uint8_t expected_hmac[32] = {
	0x2e, 0x47, 0x95, 0x1f, 0xb3, 0x8e, 0x5a, 0xdf, 0x4c, 0x2c, 0xb4,
	0xdf, 0xc4, 0xfe, 0x51, 0x7e, 0x4e, 0x06, 0x2f, 0x27, 0xda, 0x75,
	0x25, 0x7a, 0xc4, 0x32, 0x4b, 0xd6, 0x6d, 0x10, 0xa9, 0xe0,
};

static uint8_t expected_long_hmac[32] = {
	0xb8, 0xc7, 0xbb, 0x71, 0x82, 0xd0, 0x1f, 0xb4, 0x4c, 0x7e, 0x4f,
	0xd7, 0xd1, 0x40, 0xcf, 0x60, 0x1e, 0x0f, 0x9a, 0x1e, 0xdb, 0x4c,
	0x73, 0xf8, 0x33, 0xc0, 0x77, 0xa2, 0x35, 0xa5, 0xa9, 0xe8,
};

static uint8_t expected_cmac[16] = {
	0xc9, 0x09, 0x74, 0x42, 0xd2, 0x6a, 0x10, 0xff,
	0x13, 0xcc, 0x2a, 0xa2, 0x3b, 0xbe, 0xc2, 0xef,
};

static uint8_t expected_long_cmac[16] = {
	0x41, 0x0a, 0x6f, 0x2b, 0x4c, 0xab, 0xe6, 0xe7,
	0x8d, 0xe8, 0x9f, 0xf2, 0x80, 0xd2, 0xe2, 0x8e,
};

void test_mac(bool generate_key, psa_key_location_t location, const uint8_t *input,
	      size_t input_len, const uint8_t *expected, size_t expected_len, psa_algorithm_t alg,
	      psa_key_type_t type)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	uint8_t mac[32] = {0};
	size_t mac_len = 0;

	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, alg);
	psa_set_key_type(&attributes, type);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
						  PSA_KEY_PERSISTENCE_VOLATILE, location));
	if (generate_key) {
		zassert_equal(psa_generate_key(&attributes, &key_id), PSA_SUCCESS,
			      "Failed to generate key");
	} else {
		zassert_equal(psa_import_key(&attributes, key, sizeof(key), &key_id), PSA_SUCCESS,
			      "Failed to import key");
	}

	zassert_equal(psa_mac_compute(key_id, alg, input, input_len, mac, sizeof(mac), &mac_len),
		      PSA_SUCCESS, "Failed to perform MAC operation");

	zassert_equal(mac_len, expected_len, "MAC length mismatch");
	if (!generate_key && expected) {
		zassert_mem_equal(mac, expected, expected_len);
	}

	zassert_equal(psa_mac_verify(key_id, alg, input, input_len, mac, mac_len), PSA_SUCCESS,
		      "Failed to verify MAC");
}

ZTEST(psa_crypto_test, test_mac_hmac_transparent)
{
	test_mac(false, 0, plaintext, sizeof(plaintext), expected_hmac, sizeof(expected_hmac),
		 PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_KEY_TYPE_HMAC);
	test_mac(true, 0, plaintext, sizeof(plaintext), NULL, 32, PSA_ALG_HMAC(PSA_ALG_SHA_256),
		 PSA_KEY_TYPE_HMAC);
}

ZTEST(psa_crypto_test, test_mac_hmac_long_transparent)
{
	test_mac(false, 0, long_plaintext, sizeof(long_plaintext), expected_long_hmac,
		 sizeof(expected_long_hmac), PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_KEY_TYPE_HMAC);
	test_mac(true, 0, long_plaintext, sizeof(long_plaintext), NULL, 32,
		 PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_KEY_TYPE_HMAC);
}

ZTEST(psa_crypto_test, test_mac_cmac_transparent)
{
	test_mac(false, 0, plaintext, sizeof(plaintext), expected_cmac, sizeof(expected_cmac),
		 PSA_ALG_CMAC, PSA_KEY_TYPE_AES);
	test_mac(true, 0, plaintext, sizeof(plaintext), NULL, 16, PSA_ALG_CMAC, PSA_KEY_TYPE_AES);
}

ZTEST(psa_crypto_test, test_mac_cmac_long_transparent)
{
	test_mac(false, 0, long_plaintext, sizeof(long_plaintext), expected_long_cmac,
		 sizeof(expected_long_cmac), PSA_ALG_CMAC, PSA_KEY_TYPE_AES);
	test_mac(true, 0, long_plaintext, sizeof(long_plaintext), NULL, 16, PSA_ALG_CMAC,
		 PSA_KEY_TYPE_AES);
}
