/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * 1 kHz sine-wave audio source for the clock-validation test.
 *
 * The sibling files sine_{8k,16k,44k,48k}.c each carry the 1 kHz tone in
 * two mono arrays:
 *
 *   sine1khz_16bit_mono_pcm_<rate>
 *   sine1khz_32bit_mono_pcm_<rate>
 *
 * CMakeLists.txt links exactly one sine_*.c based on -DFRAME_CLK_HZ; this
 * file then picks one array at compile time from WORD_SIZE_BITS (16 vs 32).
 * The linker drops the other via --gc-sections, so per-build flash stays minimal.
 *
 * PLAYBACK_LOOP (CMake PLAYBACK_MODE):
 *   0 (one_shot) : play the clip exactly once, then audio_is_done() returns
 *                  true and audio_fill_*() emit silence.
 *   1 (loopback) : wrap the cursor forever -- ideal for sustained scope /
 *                  FFT capture during SRS 2.b verification.
 */

#include <string.h>

#include "../app_config.h"
#include "../audio.h"
#include "sine.h"

/* Pick the matching pre-quantized clip + a human-readable Fs string. */
#if FRAME_CLK_HZ == 8000
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_8k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_8k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_8k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_8k_len
#define CLIP_FS_LABEL     "8k"
#elif FRAME_CLK_HZ == 16000
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_16k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_16k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_16k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_16k_len
#define CLIP_FS_LABEL     "16k"
#elif FRAME_CLK_HZ == 44100
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_44k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_44k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_44k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_44k_len
#define CLIP_FS_LABEL     "44k1"
#elif FRAME_CLK_HZ == 48000
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_48k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_48k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_48k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_48k_len
#define CLIP_FS_LABEL     "48k"
#else
#error "AUDIO_SOURCE=sine1khz requires FRAME_CLK_HZ in {8000, 16000, 44100, 48000}."
#endif

/*
 * Resolution select: WORD_SIZE_BITS picks the 16- or 32-bit array.
 *
 * audio.h API is fixed at int16_t output, so when WORD_SIZE_BITS == 32 we
 * keep only the upper 16 bits of each int32_t sample (>> 16).  That preserves
 * mandatory-resolution information exactly while still pulling the actual
 * 32-bit symbol into the link map (proof: `arm-none-eabi-nm zephyr.elf |
 * grep sine1khz_32bit`).
 */
#if WORD_SIZE_BITS == 16
#define CLIP_RES_LABEL  "s16"
#define CLIP_PTR         MONO_S16_PTR /* = sine1khz_16bit_mono_pcm_16k */
#define CLIP_LEN_TOTAL   MONO_S16_LEN /* = sine1khz_16bit_mono_pcm_16k_len */
static inline int16_t fetch_s16(unsigned idx)
{
  return CLIP_PTR[idx];
}
#elif WORD_SIZE_BITS == 32
#define CLIP_RES_LABEL  "s32"
#define CLIP_PTR         MONO_S32_PTR
#define CLIP_LEN_TOTAL   MONO_S32_LEN
static inline int16_t fetch_s16(unsigned idx)
{
  return (int16_t)(CLIP_PTR[idx] >> 16);
}
#else
#error "AUDIO_SOURCE=sine1khz requires WORD_SIZE in {16, 32}."
#endif

static uint32_t cursor;   /* element index into CLIP_PTR (NOT frames) */
static bool     done;

void audio_init(void)
{
  cursor = 0U;
  done = false;
}

const char *audio_source_name(void)
{
  return "sine1khz@" CLIP_FS_LABEL "/" CLIP_RES_LABEL "/mono";
}

bool audio_is_done(void)
{
  return done;
}

/* Mono pull. */
unsigned audio_fill_mono(int16_t *dest, unsigned n)
{
  const uint32_t total = CLIP_LEN_TOTAL;
  unsigned written = 0U;

  if (done) {
    memset(dest, 0, n * sizeof(int16_t));
    return n;
  }

  while (written < n) {
    if (cursor >= total) {
#if PLAYBACK_LOOP
      cursor = 0U;
#else
      done = true;
      memset(&dest[written], 0,
             (n - written) * sizeof(int16_t));
      return n;
#endif
    }

    dest[written] = fetch_s16(cursor);
    cursor++;
    written++;
  }

  return written;
}
