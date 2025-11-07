# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

function(zephyr_runner_file type path)
  # Property magic which makes west flash choose the signed build
  # output of a given type.
  set_target_properties(runners_yaml_props_target PROPERTIES "${type}_file" "${path}")
endfunction()

function(zephyr_commander_sign_tasks keyfile)
  string(CONFIGURE "${keyfile}" keyfile)

  # Extensionless prefix of any output file.
  set(output ${ZEPHYR_BINARY_DIR}/${KERNEL_NAME})

  # List of additional build byproducts.
  set(byproducts)

  if(CONFIG_BUILD_OUTPUT_HEX)
    list(APPEND byproducts ${output}.signed.hex)
    zephyr_runner_file(hex ${output}.signed.hex)
    set(BYPRODUCT_KERNEL_SIGNED_HEX_NAME "${output}.signed.hex"
      CACHE FILEPATH "Signed kernel hex file" FORCE
    )
    set_property(GLOBAL APPEND PROPERTY extra_post_build_commands COMMAND
                  commander convert ${output}.hex
                  --secureboot --keyfile ${keyfile} -o ${output}.signed.hex)
  endif()

  set_property(GLOBAL APPEND PROPERTY extra_post_build_byproducts ${byproducts})
endfunction()

if(DEFINED CONFIG_MCUBOOT AND DEFINED CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256)
  zephyr_commander_sign_tasks("${CONFIG_BOOT_SIGNATURE_KEY_FILE}")
endif()
