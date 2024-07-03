/*
 * Copyright (c) 2023 Antmicro
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_siwx917_pinctrl

#include <zephyr/drivers/pinctrl.h>
#include "rsi_rom_egpio.h"

static void pinctrl_siwx917_set(bool use_ulp, uint8_t port, uint8_t pin, uint8_t mux)
{
	/* FIXME: References to EGPIO1 and EGPIO must be replaced by
	 * DT_REG_ADDR(DT_NODELABEL(pinctl)) (Note Siwx917 has two pinctl instances)
	 */
	if (use_ulp) {
		RSI_EGPIO_UlpPadReceiverEnable(pin);
		RSI_EGPIO_SetPinMux(EGPIO1, port, pin, mux);
	} else {
		RSI_EGPIO_HostPadsGpioModeEnable(pin);
		RSI_EGPIO_PadReceiverEnable(pin);
		RSI_EGPIO_SetPinMux(EGPIO, port, pin, mux);
	}
}

int pinctrl_configure_pins(const pinctrl_soc_pin_t *pins, uint8_t pin_cnt, uintptr_t reg)
{
	ARG_UNUSED(reg);
	int i;

	for (i = 0; i < pin_cnt; i++) {
		pinctrl_siwx917_set(pins[i].base, pins[i].port, pins[i].pin, pins[i].mux);
	}

	return 0;
}
