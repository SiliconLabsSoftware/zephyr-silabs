/*
 * Copyright (c) 2023 Antmicro
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sw_isr_table.h>
#include "rsi_rom_clks.h"
#include "rsi_rom_ulpss_clk.h"
#include "rsi_ipmu.h"

int silabs_siwx917_init(void)
{
	SystemInit();
	SystemCoreClockUpdate();

	/* Trip the clock to 32 MHz */
	RSI_Clks_Trim32MHzRC(32);

	/* FIXME: do not hardcode UART instances */
#if DT_NODE_HAS_STATUS(DT_NODELABEL(ulpuart0), okay)
	RSI_PS_UlpssPeriPowerUp(ULPSS_PWRGATE_ULP_UART);
	RSI_ULPSS_UlpUartClkConfig(ULPCLK, ENABLE_STATIC_CLK, 0, ULP_UART_REF_CLK, 0);
#endif
#if DT_NODE_HAS_STATUS(DT_NODELABEL(uart0), okay)
	RSI_CLK_UsartClkConfig(M4CLK, ENABLE_STATIC_CLK, 0, USART1, 0, 1);
#endif

	return 0;
}
SYS_INIT(silabs_siwx917_init, PRE_KERNEL_1, 0);

/* SiWx917's bootloader requires IRQn 32 to hold payload's entry point address. */
extern void z_arm_reset(void);
Z_ISR_DECLARE(32, ISR_FLAG_DIRECT, z_arm_reset, 0);
