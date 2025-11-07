# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

# Module for locating Simplicity Commander.
#
# The module defines the following variables:
#
# COMMANDER
# Path to Simplicity Commander binary
# Set to 'COMMANDER-NOTFOUND' if Commander was not found
#
# SimplicityCommander_FOUND
# True if Simplicity Commander was found.

find_program(SLT slt)
if(SLT)
  execute_process(
    COMMAND ${SLT} where commander
    OUTPUT_VARIABLE slt_output
    RESULT_VARIABLE slt_status
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(${slt_status} EQUAL 0 AND NOT slt_output STREQUAL "")
    set(slt_commander_path "${slt_output}")
  endif()
endif()

find_program(COMMANDER
  NAMES commander-cli commander NAMES_PER_DIR
  HINTS ${slt_commander_path}
  PATH_SUFFIXES Contents/MacOS
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SimplicityCommander REQUIRED_VARS COMMANDER)
