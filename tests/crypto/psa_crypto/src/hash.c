/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <psa/crypto.h>

#include "test_vectors.h"

const uint8_t expect_sha256_hash[32] = {
	0xeb, 0x82, 0x57, 0x4e, 0x4b, 0x80, 0x69, 0xe7, 0xcc, 0x2d, 0xf8,
	0xb1, 0x2c, 0x85, 0xb7, 0x4b, 0x40, 0x9f, 0x26, 0xb5, 0x48, 0x51,
	0x0b, 0x45, 0x1a, 0x4b, 0xf2, 0xcb, 0x81, 0xfd, 0x46, 0x76,
};

ZTEST(psa_crypto_test, test_hash_sha256)
{
	uint8_t hash_buf[32];
	size_t hash_len;

	zassert_equal(psa_hash_compute(PSA_ALG_SHA_256, plaintext, sizeof(plaintext), hash_buf,
				       sizeof(hash_buf), &hash_len),
		      PSA_SUCCESS, "Failed to compute hash");
	zassert_equal(hash_len, sizeof(expect_sha256_hash), "Hash length mismatch");
	zassert_mem_equal(hash_buf, expect_sha256_hash, sizeof(expect_sha256_hash),
			  "Hash mismatch");

	zassert_equal(psa_hash_compare(PSA_ALG_SHA_256, plaintext, sizeof(plaintext),
				       expect_sha256_hash, sizeof(expect_sha256_hash)),
		      PSA_SUCCESS, "Failed to compare hash");
}

ZTEST(psa_crypto_test, test_hash_sha256_multipart)
{
	uint8_t hash_buf[32];
	size_t hash_len;
	uint32_t stream_block_size = 128;
	size_t hash_total = 0;
	psa_hash_operation_t hash_op = psa_hash_operation_init();

	zassert_equal(psa_hash_setup(&hash_op, PSA_ALG_SHA_256), PSA_SUCCESS,
		      "Failed to setup hash");

	while ((sizeof(plaintext) - hash_total) > stream_block_size) {
		zassert_equal(
			psa_hash_update(&hash_op, (plaintext + hash_total), stream_block_size),
			PSA_SUCCESS, "Failed to update hash");
		hash_total += stream_block_size;
	}
	zassert_equal(
		psa_hash_update(&hash_op, (plaintext + hash_total), sizeof(plaintext) - hash_total),
		PSA_SUCCESS, "Failed to update hash");

	zassert_equal(psa_hash_finish(&hash_op, hash_buf, sizeof(hash_buf), &hash_len), PSA_SUCCESS,
		      "Failed to finish hash");
	zassert_equal(hash_len, sizeof(expect_sha256_hash), "Hash length mismatch");
	zassert_mem_equal(hash_buf, expect_sha256_hash, sizeof(expect_sha256_hash),
			  "Hash mismatch");
}
