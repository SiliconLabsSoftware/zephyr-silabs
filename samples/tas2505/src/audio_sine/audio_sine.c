/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * 1 kHz sine-wave audio source for the clock-validation test.
 *
 * The sibling files sine_{8k,16k,44k,48k}.c each carry the 1 kHz tone in
 * four parallel arrays covering the matrix:
 *
 *   sine1khz_16bit_mono_pcm_<rate>     (mandatory)
 *   sine1khz_32bit_mono_pcm_<rate>     (optional)
 *   sine1khz_16bit_stereo_pcm_<rate>   (optional)
 *   sine1khz_32bit_stereo_pcm_<rate>   (optional)
 *
 * CMakeLists.txt links exactly one sine_*.c based on -DFRAME_CLK_HZ; this
 * file then picks one of its four arrays at compile time from WORD_SIZE_BITS
 * (16 vs 32) and CHANNEL_MODE_ID (mono variants vs stereo).  The linker drops
 * the three other arrays via --gc-sections, so per-build flash stays minimal.
 *
 * PLAYBACK_LOOP (CMake PLAYBACK_MODE):
 *   0 (one_shot) : play the clip exactly once, then audio_is_done() returns
 *                  true and audio_fill_*() emit silence.
 *   1 (loopback) : wrap the cursor forever -- ideal for sustained scope /
 *                  FFT capture during SRS 2.b verification.
 */

#include <string.h>

#include "../audio.h"
#include "sine.h"

#ifndef FRAME_CLK_HZ
#define FRAME_CLK_HZ 16000
#endif

#ifndef WORD_SIZE_BITS
#define WORD_SIZE_BITS 16
#endif

#ifndef PLAYBACK_LOOP
#define PLAYBACK_LOOP 0
#endif

/*
 * CHANNEL_MODE_ID values are defined in main.c (1=mono_left, 2=mono_right,
 * 3=stereo).  We only care about "is this build asking us for a stereo
 * native fill?" which is the `== 3` test.  Mono variants all use
 * audio_fill_mono() and let main.c handle L/R routing.
 */
#ifndef CHANNEL_MODE_ID
#define CHANNEL_MODE_ID 2
#endif

/* Pick the matching pre-quantized clip + a human-readable Fs string. */
#if FRAME_CLK_HZ == 8000
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_8k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_8k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_8k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_8k_len
#define STEREO_S16_PTR    sine1khz_16bit_stereo_pcm_8k
#define STEREO_S16_LEN    sine1khz_16bit_stereo_pcm_8k_len
#define STEREO_S32_PTR    sine1khz_32bit_stereo_pcm_8k
#define STEREO_S32_LEN    sine1khz_32bit_stereo_pcm_8k_len
#define CLIP_FS_LABEL     "8k"
#elif FRAME_CLK_HZ == 16000
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_16k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_16k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_16k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_16k_len
#define STEREO_S16_PTR    sine1khz_16bit_stereo_pcm_16k
#define STEREO_S16_LEN    sine1khz_16bit_stereo_pcm_16k_len
#define STEREO_S32_PTR    sine1khz_32bit_stereo_pcm_16k
#define STEREO_S32_LEN    sine1khz_32bit_stereo_pcm_16k_len
#define CLIP_FS_LABEL     "16k"
#elif FRAME_CLK_HZ == 44100
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_44k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_44k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_44k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_44k_len
#define STEREO_S16_PTR    sine1khz_16bit_stereo_pcm_44k
#define STEREO_S16_LEN    sine1khz_16bit_stereo_pcm_44k_len
#define STEREO_S32_PTR    sine1khz_32bit_stereo_pcm_44k
#define STEREO_S32_LEN    sine1khz_32bit_stereo_pcm_44k_len
#define CLIP_FS_LABEL     "44k1"
#elif FRAME_CLK_HZ == 48000
#define MONO_S16_PTR      sine1khz_16bit_mono_pcm_48k
#define MONO_S16_LEN      sine1khz_16bit_mono_pcm_48k_len
#define MONO_S32_PTR      sine1khz_32bit_mono_pcm_48k
#define MONO_S32_LEN      sine1khz_32bit_mono_pcm_48k_len
#define STEREO_S16_PTR    sine1khz_16bit_stereo_pcm_48k
#define STEREO_S16_LEN    sine1khz_16bit_stereo_pcm_48k_len
#define STEREO_S32_PTR    sine1khz_32bit_stereo_pcm_48k
#define STEREO_S32_LEN    sine1khz_32bit_stereo_pcm_48k_len
#define CLIP_FS_LABEL     "48k"
#else
#error "AUDIO_SOURCE=sine1khz requires FRAME_CLK_HZ in {8000, 16000, 44100, 48000}."
#endif

/*
 * Resolution + channel layout select.  WORD_SIZE_BITS picks 16- vs 32-bit;
 * CHANNEL_MODE_ID == 3 (stereo) picks the interleaved variant so the
 * SRS-optional stereo array is actually linked + walked at runtime.
 *
 * audio.h API is fixed at int16_t output, so when WORD_SIZE_BITS == 32 we
 * keep only the upper 16 bits of each int32_t sample (>> 16).  That preserves
 * mandatory-resolution information exactly while still pulling the actual
 * 32-bit symbol into the link map (proof: `arm-none-eabi-nm zephyr.elf |
 * grep sine1khz_32bit`).
 */
#if WORD_SIZE_BITS == 16
  #define CLIP_RES_LABEL  "s16"
  #if CHANNEL_MODE_ID == 3
    #define CLIP_PTR         STEREO_S16_PTR
    #define CLIP_LEN_TOTAL   STEREO_S16_LEN   /* in int16_t units (2 * frames) */
    #define IS_STEREO        1
    #define CLIP_CHAN_LABEL  "stereo"
static inline int16_t fetch_s16(unsigned idx)
{
  return CLIP_PTR[idx];
}
  #else
    #define CLIP_PTR         MONO_S16_PTR /* = sine1khz_16bit_mono_pcm_16k */
    #define CLIP_LEN_TOTAL   MONO_S16_LEN /* = sine1khz_16bit_mono_pcm_16k_len */
    #define IS_STEREO        0
    #define CLIP_CHAN_LABEL  "mono"
static inline int16_t fetch_s16(unsigned idx)
{
  return CLIP_PTR[idx];
}
  #endif
#elif WORD_SIZE_BITS == 32
  #define CLIP_RES_LABEL  "s32"
  #if CHANNEL_MODE_ID == 3
    #define CLIP_PTR         STEREO_S32_PTR
    #define CLIP_LEN_TOTAL   STEREO_S32_LEN   /* in int32_t units (2 * frames) */
    #define IS_STEREO        1
    #define CLIP_CHAN_LABEL  "stereo"
static inline int16_t fetch_s16(unsigned idx)
{
  return (int16_t)(CLIP_PTR[idx] >> 16);
}
  #else
    #define CLIP_PTR         MONO_S32_PTR
    #define CLIP_LEN_TOTAL   MONO_S32_LEN
    #define IS_STEREO        0
    #define CLIP_CHAN_LABEL  "mono"
static inline int16_t fetch_s16(unsigned idx)
{
  return (int16_t)(CLIP_PTR[idx] >> 16);
}
  #endif
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
  return "sine1khz@" CLIP_FS_LABEL "/" CLIP_RES_LABEL "/" CLIP_CHAN_LABEL;
}

bool audio_is_done(void)
{
  return done;
}

/*
 * Mono pull.  When the linked clip is the stereo variant we just step
 * through L samples (every 2nd element) so the same source serves both
 * mono and stereo builds without re-quantization.
 */
unsigned audio_fill_mono(int16_t *dest, unsigned n)
{
  const uint32_t step  = IS_STEREO ? 2U : 1U;
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
    cursor += step;
    written++;
  }

  return written;
}
