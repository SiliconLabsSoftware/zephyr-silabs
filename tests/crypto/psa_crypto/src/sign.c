/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

#if defined CONFIG_TEST_WRAPPED_KEYS
#include "sl_si91x_psa_wrap.h"
#endif

#include "test_vectors.h"

uint8_t pubkey[65];
uint8_t signature[64];
size_t pubkey_len;
size_t signature_len;
static const unsigned char private_key[] = { 0x95, 0xCD, 0x3A, 0x36, 0x25, 0xD6, 0xF6, 0x06, 0xBD, 0xC8, 0x64,
                                             0x77, 0x8D, 0x4A, 0xA6, 0x50, 0xC2, 0xD7, 0x9A, 0x05, 0x94, 0xDD,
                                             0x10, 0xCF, 0x4C, 0x47, 0x4B, 0x83, 0xD2, 0x87, 0x0D, 0x1A };
#define MESSAGE_SIZE (sizeof(plaintext) / 2)

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

	zassert_equal(psa_import_key(&attributes,private_key, sizeof(private_key), &key_id), PSA_SUCCESS,
		      "Failed to import private key");

	zassert_equal(psa_export_public_key(key_id, pubkey, sizeof(pubkey), &pubkey_len),
		      PSA_SUCCESS, "Failed to export public key");

	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy private key");

	/* Set up attributes for a volatile private plain key (secp256r1) */
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_usage_flags(&attributes,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_ANY_HASH));

	#if defined(CONFIG_TEST_WRAPPED_KEYS) && CONFIG_TEST_WRAPPED_KEYS
		printf("Test Wrapper keys enabled\n");
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
							  PSA_KEY_PERSISTENCE_VOLATILE, PSA_KEY_VOLATILE_PERSISTENT_WRAP_IMPORT));
	#endif

	zassert_equal(psa_import_key(&attributes,private_key, sizeof(private_key), &key_id), PSA_SUCCESS,
		      "Failed to import private key");
	
	zassert_equal(psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), plaintext,
				       MESSAGE_SIZE, signature, sizeof(signature), &signature_len),
		      PSA_SUCCESS, "Failed to hash-and-sign message");

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
		      PSA_SUCCESS, "Failed to verify signature");

	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy key");
}
