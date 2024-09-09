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

#include "sl_si91x_clock_manager.h"

int silabs_siwx917_init(void)
{
	SystemInit();
	SystemCoreClockUpdate();

	/* Use SoC PLL at configured frequency as core clock */
	sl_si91x_clock_manager_m4_set_core_clk(M4_SOCPLLCLK,
					       CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC);

	/* Use interface PLL at configured frequency as peripheral clock */
	sl_si91x_clock_manager_set_pll_freq(INFT_PLL,
					    CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC,
					    PLL_REF_CLK_VAL_XTAL);

	/* FIXME: do not hardcode UART instances */
#if DT_NODE_HAS_STATUS(DT_NODELABEL(ulpuart0), okay)
	RSI_ULPSS_UlpUartClkConfig(ULPCLK, ENABLE_STATIC_CLK, 0, ULP_UART_ULP_32MHZ_RC_CLK, 1);
#endif
#if DT_NODE_HAS_STATUS(DT_NODELABEL(uart1), okay)
	RSI_CLK_UsartClkConfig(M4CLK, ENABLE_STATIC_CLK, 0, USART1, 0, 1);
#endif
#if DT_NODE_HAS_STATUS(DT_NODELABEL(uart2), okay)
	RSI_CLK_UsartClkConfig(M4CLK, ENABLE_STATIC_CLK, 0, USART2, 0, 1);
#endif
#if DT_NODE_HAS_STATUS(DT_NODELABEL(i2c0), okay)
	RSI_PS_M4ssPeriPowerUp(M4SS_PWRGATE_ULP_EFUSE_PERI);
	RSI_CLK_I2CClkConfig(M4CLK, true, 0);
#endif
#if DT_NODE_HAS_STATUS(DT_NODELABEL(i2c1), okay)
	RSI_PS_M4ssPeriPowerUp(M4SS_PWRGATE_ULP_EFUSE_PERI);
	RSI_CLK_I2CClkConfig(M4CLK, true, 1);
#endif
#if DT_NODE_HAS_STATUS(DT_NODELABEL(ulpi2c), okay)
	RSI_PS_UlpssPeriPowerUp(ULPSS_PWRGATE_ULP_I2C);
	RSI_ULPSS_PeripheralEnable(ULPCLK, ULP_I2C_CLK, ENABLE_STATIC_CLK);
#endif

	return 0;
}
SYS_INIT(silabs_siwx917_init, PRE_KERNEL_1, 0);

/* SiWx917's bootloader requires IRQn 32 to hold payload's entry point address. */
extern void z_arm_reset(void);
Z_ISR_DECLARE(32, ISR_FLAG_DIRECT, z_arm_reset, 0);
