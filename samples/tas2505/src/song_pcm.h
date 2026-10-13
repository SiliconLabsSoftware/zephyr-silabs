/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mono 16-bit signed PCM samples (sample rate must match FRAME_CLK_HZ).
 *
 * Flash budget (xG27 ~768 KiB): embedding large clips overflows rodata. As a
 * rule of thumb stay under ~500 KiB PCM (~15 s @ 16 kHz mono s16), or use lower
 * fs / shorter duration / external storage.
 * Generate song_pcm.c with wav2c (https://github.com/tuna-f1sh/wav2c):
 *
 *   ffmpeg -i your_song.mp3 -t 15 -ac 1 -ar 16000 -sample_fmt s16 song.wav
 *   wav2c -o song_pcm.c --array-name song_pcm song.wav
 *
 * Make sure -ar matches FRAME_CLK_HZ in your build (-DFRAME_CLK_HZ=16000).
 */

#ifndef SONG_PCM_H
#define SONG_PCM_H

#include <stddef.h>
#include <stdint.h>

extern const size_t SONG_PCM_SAMPLE_NO;

/* Mono s16 PCM; main.c expands to 32-bit I2S slots when WORD_SIZE_BITS=32. */
extern const int16_t song_pcm[];

#endif /* SONG_PCM_H */
