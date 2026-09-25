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
  src/mac.c
  src/sign.c
  src/key_agreement.c
)

# Use CMake variables to configure testcase, since Kconfig can't be defined
# in out-of-tree tests due to the compliance script failing.

# HSE fully supports opaque keys and multipart operations
dt_nodelabel(se_path NODELABEL "se")
if(CONFIG_SILABS_SISDK_PSA_CRYPTO AND DEFINED se_path)
  target_compile_definitions(app PUBLIC
    TEST_OPAQUE_AEAD=1
    TEST_OPAQUE_CIPHER=1
    TEST_OPAQUE_KEY_AGREEMENT=1
    TEST_OPAQUE_SIGN=1
  )
  # SixG301 does not hardware accelerate ChaCha20, so opaque keys can't be used
  if(CONFIG_SOC_FAMILY_SILABS_S3_SIX301)
    target_compile_definitions(app PUBLIC
      TEST_OPAQUE_NO_CHACHA=1
    )
  endif()
endif()

# SiWx917 only supports one-shot operations on internally generated opaque keys
# for sign_message/verify_message and AEAD encrypt/decrypt
if(CONFIG_SILABS_WISECONNECT_PSA_CRYPTO)
  target_compile_definitions(app PUBLIC
    TEST_OPAQUE_AEAD=1
    # Disable opaque signing test while hardware acceleration is disabled
    # TEST_OPAQUE_SIGN=1
    TEST_OPAQUE_NO_IMPORT_KEY=1
    TEST_OPAQUE_NO_MULTIPART=1
    TEST_OPAQUE_NO_VERIFY=1
  )
endif()
