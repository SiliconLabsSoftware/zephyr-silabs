# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(siwg917)

set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
    COMMAND commander rps create --app ${KERNEL_ELF_NAME} ${KERNEL_ELF_NAME}.rps
)
