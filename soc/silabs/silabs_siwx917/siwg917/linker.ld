/*
 * Copyright (c) 2023 Antmicro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/arch/arm/cortex_m/scripts/linker.ld>

SECTIONS
{
	.common_tcm_code :
	{
		*(.common_tcm_code*)
	} > FLASH
}
