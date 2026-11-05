/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Opaque stub so stock sl_cli_types.h can compile without SiSDK iostream.
 * Not a functional iostream implementation — do not call sl_iostream_* APIs.
 */

#ifndef SL_IOSTREAM_H
#define SL_IOSTREAM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sl_iostream {
	void *unused;
} sl_iostream_t;

#ifdef __cplusplus
}
#endif

#endif /* SL_IOSTREAM_H */
