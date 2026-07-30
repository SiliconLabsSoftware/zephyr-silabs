/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr PLATFORM_HEADER for Zigbee SDK / App Framework sources.
 * Provides the legacy types and macros those sources expect; omit
 * SiSDK diagnostic/linker-segment pieces unused by the Zephyr build.
 */

#ifndef PLATFORM_HEADER_H
#define PLATFORM_HEADER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TRUE  1u
#define FALSE 0u

typedef bool boolean;
typedef uint8_t int8u;
typedef int8_t int8s;
typedef uint16_t int16u;
typedef int16_t int16s;
typedef uint32_t int32u;
typedef int32_t int32s;
typedef uint64_t int64u;
typedef int64_t int64s;

#ifndef __SOURCEFILE__
#define __SOURCEFILE__ __FILE__
#endif

#ifndef UNUSED_VAR
#define UNUSED_VAR(x) (void)(x)
#endif

#if defined(__GNUC__)
#define UNUSED         __attribute__((unused))
#define WEAK(__symbol) __attribute__((weak)) __symbol
#endif

#define LOW_BYTE(n)                     ((uint8_t)((n) & 0xFF))
#define HIGH_BYTE(n)                    ((uint8_t)(LOW_BYTE((n) >> 8)))
#define HIGH_LOW_TO_INT(high, low) \
	(((((uint16_t)(high)) << 8) + ((uint16_t)((low) & 0xFF))))
#define BIT(x)                          (1U << (x))
#define BIT32(x)                        (((uint32_t)1) << (x))
#define BYTE_0(n)                       ((uint8_t)((n) & 0xFF))
#define BYTE_1(n)                       BYTE_0((n) >> 8)
#define BYTE_2(n)                       BYTE_0((n) >> 16)
#define BYTE_3(n)                       BYTE_0((n) >> 24)

#define SETBIT(reg, bit)                ((reg) |= BIT(bit))
#define SETBITS(reg, bits)              ((reg) |= (bits))
#define CLEARBIT(reg, bit)              ((reg) &= ~(BIT(bit)))
#define CLEARBITS(reg, bits)            ((reg) &= ~(bits))
#define READBIT(reg, bit)               ((reg) & (BIT(bit)))
#define READBITS(reg, bits)             ((reg) & (bits))
#define COUNTOF(a)                      (sizeof(a) / sizeof((a)[0]))

#define elapsedTimeInt8u(oldTime, newTime) \
	((uint8_t)((uint8_t)(newTime) - (uint8_t)(oldTime)))
#define elapsedTimeInt16u(oldTime, newTime) \
	((uint16_t)((uint16_t)(newTime) - (uint16_t)(oldTime)))
#define elapsedTimeInt32u(oldTime, newTime) \
	((uint32_t)((uint32_t)(newTime) - (uint32_t)(oldTime)))

#define MAX_INT8U_VALUE                 (0xFF)
#define HALF_MAX_INT8U_VALUE            (0x80)
#define timeGTorEqualInt8u(t1, t2) \
	(elapsedTimeInt8u(t2, t1) <= (HALF_MAX_INT8U_VALUE))

#define MAX_INT16U_VALUE                (0xFFFF)
#define HALF_MAX_INT16U_VALUE           (0x8000)
#define timeGTorEqualInt16u(t1, t2) \
	(elapsedTimeInt16u(t2, t1) <= (HALF_MAX_INT16U_VALUE))

#define MAX_INT32U_VALUE                (0xFFFFFFFFUL)
#define HALF_MAX_INT32U_VALUE           (0x80000000UL)
#define timeGTorEqualInt32u(t1, t2) \
	(elapsedTimeInt32u(t2, t1) <= (HALF_MAX_INT32U_VALUE))

#include "sl_core.h"
#include "sl_common.h"

#define DECLARE_INTERRUPT_STATE         CORE_DECLARE_IRQ_STATE
#define DISABLE_INTERRUPTS()            CORE_ENTER_ATOMIC()
#define RESTORE_INTERRUPTS()            CORE_EXIT_ATOMIC()
#define INTERRUPTS_ON()                 CORE_ATOMIC_IRQ_ENABLE()
#define INTERRUPTS_OFF()                CORE_ATOMIC_IRQ_DISABLE()
#define ATOMIC(blah)                    CORE_ATOMIC_SECTION(blah)

#ifndef MILLISECOND_TICKS_PER_SECOND
#define MILLISECOND_TICKS_PER_SECOND 1000UL
#endif
#ifndef MILLISECOND_TICKS_PER_QUARTERSECOND
#define MILLISECOND_TICKS_PER_QUARTERSECOND (MILLISECOND_TICKS_PER_SECOND >> 2)
#endif
#ifndef MILLISECOND_TICKS_PER_MINUTE
#define MILLISECOND_TICKS_PER_MINUTE (60UL * MILLISECOND_TICKS_PER_SECOND)
#endif
#ifndef MILLISECOND_TICKS_PER_HOUR
#define MILLISECOND_TICKS_PER_HOUR (60UL * MILLISECOND_TICKS_PER_MINUTE)
#endif

void halInternalAssertFailed(const char *filename, int linenumber);

#include "sl_zigbee_config.h"

#ifndef APP_SERIAL
#define APP_SERIAL 0
#endif

#ifndef EZSP_HOST
#undef assert
#define assert(condition) \
	do { \
		if (!(condition)) { \
			halInternalAssertFailed(__SOURCEFILE__, __LINE__); \
		} \
	} while (0)
#endif /* EZSP_HOST */

#endif /* PLATFORM_HEADER_H */
