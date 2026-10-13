/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AUDIO_H
#define AUDIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Mono int16_t source; main.c applies WORD_SIZE_BITS / stereo duplicate.
 *
 * Playback is one-shot: once the underlying clip / playlist has been pulled
 * once, audio_is_done() returns true and audio_fill_mono() emits silence so
 * main.c can flush a clean tail before stopping the I2S engine.
 */
void audio_init(void);
const char *audio_source_name(void);
unsigned audio_fill_mono(int16_t *dest, unsigned n);
bool audio_is_done(void);

#endif /* AUDIO_H */
