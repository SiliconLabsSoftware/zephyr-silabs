/*
 * Copyright (c) 2023 Antmicro
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sw_isr_table.h>
#include "rsi_rom_clks.h"
#include "rsi_rom_ulpss_clk.h"

#include "sl_si91x_clock_manager.h"

int silabs_siwx917_init(void)
{
	SystemInit();
	return 0;
}
SYS_INIT(silabs_siwx917_init, PRE_KERNEL_1, 0);

/* SiWx917's bootloader requires IRQn 32 to hold payload's entry point address. */
extern void z_arm_reset(void);
Z_ISR_DECLARE(32, ISR_FLAG_DIRECT, z_arm_reset, 0);
