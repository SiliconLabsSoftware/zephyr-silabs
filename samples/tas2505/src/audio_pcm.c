/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Embedded song_pcm[] (MP3/ffmpeg or wav2c). Requires AUDIO_SOURCE_PCM=1.
 *
 * PLAYBACK_LOOP (CMake PLAYBACK_MODE):
 *   0 (one_shot, default): play the buffer exactly once, then audio_is_done()
 *                          returns true and audio_fill_mono() emits silence.
 *   1 (loopback):          wrap the buffer to the start forever; audio_is_done()
 *                          stays false so main.c never tears down the engine.
 */

#include <string.h>

#include "audio.h"
#include "song_pcm.h"

#ifndef PLAYBACK_LOOP
#define PLAYBACK_LOOP 0
#endif

static uint32_t pcm_idx;
static bool done;

void audio_init(void)
{
  pcm_idx = 0U;
  done = false;
}

const char *audio_source_name(void)
{
  return "song_pcm";
}

bool audio_is_done(void)
{
  return done;
}

unsigned audio_fill_mono(int16_t *dest, unsigned n)
{
  const uint32_t total = (uint32_t)SONG_PCM_SAMPLE_NO;
  unsigned written = 0U;

  if (done) {
    memset(dest, 0, n * sizeof(int16_t));
    return n;
  }

  while (written < n) {
    if (pcm_idx >= total) {
#if PLAYBACK_LOOP
      /* loopback mode: rewind to the start of the clip. */
      pcm_idx = 0U;
#else
      /* one-shot mode: mark done and pad with silence. */
      done = true;
      memset(&dest[written], 0,
             (n - written) * sizeof(int16_t));
      return n;
#endif
    }

    unsigned chunk = n - written;

    if (pcm_idx + chunk > total) {
      chunk = total - pcm_idx;
    }

    for (unsigned i = 0U; i < chunk; i++) {
      dest[written + i] = song_pcm[pcm_idx + i];
    }

    pcm_idx += chunk;
    written += chunk;
  }

  return written;
}
