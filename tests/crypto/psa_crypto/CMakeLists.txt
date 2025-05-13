# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(psa_crypto)

target_sources(app PRIVATE
	src/main.c
	src/test_vectors.c
	src/aead.c
	src/cipher.c
	src/hash.c
	src/sign.c
	src/key_agreement.c
)

# Use CMake variable to configure testcase, since Kconfig can't be defined
# in out-of-tree tests due to the compliance script failing.
if(DEFINED TEST_WRAPPED_KEYS)
target_compile_definitions(app PUBLIC TEST_WRAPPED_KEYS=${TEST_WRAPPED_KEYS})
endif()
