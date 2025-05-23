/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

const uint8_t aes_key_buf[] = {0xea, 0x4f, 0x6f, 0x3c, 0x2f, 0xed, 0x2b, 0x9d,
			       0xd9, 0x70, 0x8c, 0x2e, 0x72, 0x1a, 0xe0, 0x0f};
const uint8_t aes_nonce_buf[] = {0xf9, 0x75, 0x80, 0x9d, 0xdb, 0x51,
				 0x72, 0x38, 0x27, 0x45, 0x63, 0x4f};
const uint8_t aes_ad_buf[] = {0x5c, 0x65, 0xd4, 0xf2, 0x61, 0xd2, 0xc5, 0x4f, 0xfe, 0x6a};
const uint8_t aes_plaintext[] = {0x8d, 0x6c, 0x08, 0x44, 0x6c, 0xb1, 0x0d, 0x9a, 0x20, 0x75};

const uint8_t chachapoly_key_buf[] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				      0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
				      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
				      0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
const uint8_t chachapoly_nonce_buf[] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
					0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
const uint8_t chachapoly_ad_buf[] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
				     0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
const uint8_t chachapoly_plaintext[] = {
	0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
	0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
	0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
	0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
	0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70,
	0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
	0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75,
	0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e};
const uint8_t chachapoly_expect_cipher_tag_buf[] = {
	0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
	0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
	0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
	0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
	0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
	0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
	0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
	0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
	0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
};

ZTEST(psa_crypto_test, test_aead_aes_ccm)
{
	const uint8_t expect_cipher_tag_buf[] = {
		0xe2, 0x2f, 0x37, 0x3b, 0xeb, 0xf6, 0x4a, 0x3e, 0x9b, 0x87, 0x75, 0x2b, 0xf9,
		0xdb, 0x34, 0xdc, 0x4d, 0x43, 0x3f, 0x00, 0xf5, 0x5c, 0x3f, 0x53, 0x0c, 0x89,
	};
	uint8_t cipher_tag_buf[32] = {0};
	uint8_t decrypted[sizeof(aes_plaintext)] = {0};
	size_t out_len;

	psa_key_id_t key_id;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = PSA_ALG_CCM;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, alg);

	zassert_equal(psa_import_key(&attributes, aes_key_buf, sizeof(aes_key_buf), &key_id),
		      PSA_SUCCESS, "Failed to import key");

	zassert_equal(psa_aead_encrypt(key_id, alg, aes_nonce_buf, sizeof(aes_nonce_buf),
				       aes_ad_buf, sizeof(aes_ad_buf), aes_plaintext,
				       sizeof(aes_plaintext), cipher_tag_buf,
				       sizeof(cipher_tag_buf), &out_len),
		      PSA_SUCCESS, "Failed to encrypt");

	zassert_equal(out_len, sizeof(expect_cipher_tag_buf));
	zassert_mem_equal(cipher_tag_buf, expect_cipher_tag_buf, sizeof(expect_cipher_tag_buf));

	zassert_equal(psa_aead_decrypt(key_id, alg, aes_nonce_buf, sizeof(aes_nonce_buf),
				       aes_ad_buf, sizeof(aes_ad_buf), cipher_tag_buf, out_len,
				       decrypted, sizeof(decrypted), &out_len),
		      PSA_SUCCESS, "Failed to decrypt");

	zassert_equal(out_len, sizeof(aes_plaintext));
	zassert_mem_equal(decrypted, aes_plaintext, sizeof(aes_plaintext));

	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy key");
}

ZTEST(psa_crypto_test, test_aead_aes_gcm)
{
	const uint8_t expect_cipher_tag_buf[] = {
		0x0f, 0x51, 0xf7, 0xa8, 0x3c, 0x5b, 0x5a, 0xa7, 0x96, 0xb9, 0x70, 0x25, 0x9c,
		0xdd, 0xfe, 0x8f, 0x9a, 0x15, 0xa5, 0xc5, 0xeb, 0x48, 0x5a, 0xf5, 0x78, 0xfb,
	};
	uint8_t cipher_tag_buf[32];
	uint8_t decrypted[sizeof(aes_plaintext)] = {0};
	size_t out_len;

	psa_key_id_t key_id;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = PSA_ALG_GCM;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, alg);

	zassert_equal(psa_import_key(&attributes, aes_key_buf, sizeof(aes_key_buf), &key_id),
		      PSA_SUCCESS, "Failed to import key");

	zassert_equal(psa_aead_encrypt(key_id, alg, aes_nonce_buf, sizeof(aes_nonce_buf),
				       aes_ad_buf, sizeof(aes_ad_buf), aes_plaintext,
				       sizeof(aes_plaintext), cipher_tag_buf,
				       sizeof(cipher_tag_buf), &out_len),
		      PSA_SUCCESS, "Failed to encrypt");

	zassert_equal(out_len, sizeof(expect_cipher_tag_buf));
	zassert_mem_equal(cipher_tag_buf, expect_cipher_tag_buf, sizeof(expect_cipher_tag_buf));

	zassert_equal(psa_aead_decrypt(key_id, alg, aes_nonce_buf, sizeof(aes_nonce_buf),
				       aes_ad_buf, sizeof(aes_ad_buf), cipher_tag_buf, out_len,
				       decrypted, sizeof(decrypted), &out_len),
		      PSA_SUCCESS, "Failed to decrypt");

	zassert_equal(out_len, sizeof(aes_plaintext));
	zassert_mem_equal(decrypted, aes_plaintext, sizeof(aes_plaintext));

	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy key");
}

ZTEST(psa_crypto_test, test_aead_chacha20_poly1305)
{
	uint8_t cipher_tag_buf[130]; /* Ciphertext + Tag */
	uint8_t decrypted[sizeof(chachapoly_plaintext)] = {0};
	size_t out_len;

	psa_key_id_t key_id;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_algorithm_t alg = PSA_ALG_CHACHA20_POLY1305;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attributes, alg);

	zassert_equal(psa_import_key(&attributes, chachapoly_key_buf, sizeof(chachapoly_key_buf),
				     &key_id),
		      PSA_SUCCESS, "Failed to import key");

	zassert_equal(psa_aead_encrypt(key_id, alg, chachapoly_nonce_buf,
				       sizeof(chachapoly_nonce_buf), chachapoly_ad_buf,
				       sizeof(chachapoly_ad_buf), chachapoly_plaintext,
				       sizeof(chachapoly_plaintext), cipher_tag_buf,
				       sizeof(cipher_tag_buf), &out_len),
		      PSA_SUCCESS, "Failed to encrypt");

	zassert_equal(out_len, sizeof(chachapoly_expect_cipher_tag_buf));
	zassert_mem_equal(cipher_tag_buf, chachapoly_expect_cipher_tag_buf,
			  sizeof(chachapoly_expect_cipher_tag_buf));

	zassert_equal(psa_aead_decrypt(key_id, alg, chachapoly_nonce_buf,
				       sizeof(chachapoly_nonce_buf), chachapoly_ad_buf,
				       sizeof(chachapoly_ad_buf), cipher_tag_buf, out_len,
				       decrypted, sizeof(decrypted), &out_len),
		      PSA_SUCCESS, "Failed to decrypt");

	zassert_equal(out_len, sizeof(chachapoly_plaintext));
	zassert_mem_equal(decrypted, chachapoly_plaintext, sizeof(chachapoly_plaintext));

	zassert_equal(psa_destroy_key(key_id), PSA_SUCCESS, "Failed to destroy key");
}
