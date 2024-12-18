/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

#include "test_vectors.h"

uint8_t pubkey[65];
uint8_t signature[64];
size_t pubkey_len;
size_t signature_len;

#define MESSAGE_SIZE (sizeof(plaintext) / 8)

ZTEST(psa_crypto_test, test_sign_ecdsa_secp256r1)
{
	psa_key_id_t key_id;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Set up attributes for a volatile private plain key (secp256r1) */
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));
	if (IS_ENABLED(TEST_WRAPPED_KEYS)) {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
							  PSA_KEY_PERSISTENCE_VOLATILE, 1));
	}

	zassert_equal(psa_generate_key(&attributes, &key_id), PSA_SUCCESS,
		      "Failed to generate private key");

	zassert_equal(psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), plaintext,
				       MESSAGE_SIZE, signature, sizeof(signature), &signature_len),
		      PSA_SUCCESS, "Failed to hash-and-sign message");
	zassert_equal(psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), plaintext,
					 MESSAGE_SIZE, signature, signature_len),
		      PSA_SUCCESS, "Failed to verify message");
	zassert_equal(psa_export_public_key(key_id, pubkey, sizeof(pubkey), &pubkey_len),
		      PSA_SUCCESS, "Failed to export public key");
	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy private key");

	/* Set up attributes for a public key (secp256r1) */
	attributes = psa_key_attributes_init();
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));

	zassert_equal(psa_import_key(&attributes, pubkey, sizeof(pubkey), &key_id), PSA_SUCCESS,
		      "Failed to import public key");
	zassert_equal(psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), plaintext,
					 MESSAGE_SIZE, signature, signature_len),
		      PSA_SUCCESS, "Failed to verify message");
	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy key");
}
