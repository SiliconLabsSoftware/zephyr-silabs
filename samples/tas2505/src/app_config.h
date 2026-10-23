/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fallback defaults when CMake target_compile_definitions are absent (e.g. IDE).
 */

#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#ifndef PLAYBACK_LOOP
#define PLAYBACK_LOOP           0
#endif

#ifndef FRAME_CLK_HZ
#define FRAME_CLK_HZ            16000
#endif

#ifndef WORD_SIZE_BITS
#define WORD_SIZE_BITS          16
#endif

#ifndef CHANNEL_MODE_NAME
#define CHANNEL_MODE_NAME       "mono_right"
#endif

#ifndef PLAYBACK_MODE_NAME
#define PLAYBACK_MODE_NAME      "one_shot"
#endif

#endif /* APP_CONFIG_H */
