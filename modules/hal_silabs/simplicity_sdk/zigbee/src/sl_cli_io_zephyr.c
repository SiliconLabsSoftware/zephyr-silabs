/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr replacement for SiSDK sl_cli_io.c (no sl_iostream).
 */

#include <stdarg.h>
#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/shell/shell.h>

#include "sli_cli_io.h"
#include "sl_cli_io_zephyr.h"

static const struct shell *sli_cli_shell;

void sl_cli_io_zephyr_set_shell(const struct shell *sh)
{
	sli_cli_shell = sh;
}

int sli_cli_io_getchar(void)
{
	/* Shell supplies complete lines; character tick input is unused. */
	return EOF;
}

int sli_cli_io_putchar(int ch)
{
	char c = (char)ch;

	if (sli_cli_shell != NULL) {
		shell_fprintf(sli_cli_shell, SHELL_NORMAL, "%c", c);
	} else {
		printk("%c", c);
	}

	return ch;
}

int sli_cli_io_printf(const char *format, ...)
{
	va_list argptr;

	va_start(argptr, format);
	if (sli_cli_shell != NULL) {
		shell_vfprintf(sli_cli_shell, SHELL_NORMAL, format, argptr);
	} else {
		vprintk(format, argptr);
	}
	va_end(argptr);

	return 0;
}
