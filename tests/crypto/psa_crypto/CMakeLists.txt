# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Silicon Laboratories Inc.

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

# Use CMake variables to configure testcase, since Kconfig can't be defined
# in out-of-tree tests due to the compliance script failing.

# HSE fully supports opaque keys and multipart operations
if(CONFIG_PSA_CRYPTO_DRIVER_SILABS_HSE)
target_compile_definitions(app PUBLIC
  TEST_OPAQUE_AEAD=1
  TEST_OPAQUE_CIPHER=1
  TEST_OPAQUE_KEY_AGREEMENT=1
  TEST_OPAQUE_SIGN=1
)
endif()
endif()
