# Copyright (c) 2024 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

board_runner_args(silabs_commander "--device=SiWG917M111GTBA" "--file-type=bin"
    "--file=${PROJECT_BINARY_DIR}/${KERNEL_BIN_NAME}.rps")
include(${ZEPHYR_BASE}/boards/common/silabs_commander.board.cmake)
