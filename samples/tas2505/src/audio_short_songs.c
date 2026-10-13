/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Runtime synthesis of short public-domain melodies. Timing uses FRAME_CLK_HZ
 * (sample rate); output is always int16_t mono (main.c handles WORD_SIZE_BITS).
 *
 * PLAYBACK_LOOP (CMake PLAYBACK_MODE):
 *   0 (one_shot): play the playlist exactly once, then audio_is_done() returns
 *                 true and next_sample() emits silence.
 *   1 (loopback): wrap the playlist to the first song forever; audio_is_done()
 *                 stays false.
 */

#include <string.h>

#include "audio.h"

#ifndef FRAME_CLK_HZ
#define FRAME_CLK_HZ 16000
#endif

#ifndef PLAYBACK_LOOP
#define PLAYBACK_LOOP 0
#endif

#define SINE_TABLE_LEN 64
#define SONG_GAP_MS    400U
#define BEAT_MS        300U

/* Hz; 0 = rest */
enum {
  HZ_REST = 0,
  HZ_C4 = 262, HZ_D4 = 294, HZ_E4 = 330, HZ_F4 = 349,
  HZ_G4 = 392, HZ_A4 = 440, HZ_B4 = 494,
  HZ_C5 = 523, HZ_D5 = 587, HZ_E5 = 659, HZ_F5 = 698,
  HZ_G5 = 784, HZ_A5 = 880,
};

struct note_entry {
  uint16_t hz;
  uint16_t dur_ms;
};

/* Ode to Joy (public domain) */
static const struct note_entry ode_to_joy[] = {
  { HZ_E4, BEAT_MS }, { HZ_E4, BEAT_MS }, { HZ_F4, BEAT_MS }, { HZ_G4, BEAT_MS },
  { HZ_G4, BEAT_MS }, { HZ_F4, BEAT_MS }, { HZ_E4, BEAT_MS }, { HZ_D4, BEAT_MS },
  { HZ_C4, BEAT_MS }, { HZ_C4, BEAT_MS }, { HZ_D4, BEAT_MS }, { HZ_E4, BEAT_MS },
  { HZ_E4, BEAT_MS + BEAT_MS / 2U }, { HZ_D4, BEAT_MS / 2U }, { HZ_D4, 2U * BEAT_MS },
  { HZ_E4, BEAT_MS }, { HZ_E4, BEAT_MS }, { HZ_F4, BEAT_MS }, { HZ_G4, BEAT_MS },
  { HZ_G4, BEAT_MS }, { HZ_F4, BEAT_MS }, { HZ_E4, BEAT_MS }, { HZ_D4, BEAT_MS },
  { HZ_C4, BEAT_MS }, { HZ_C4, BEAT_MS }, { HZ_D4, BEAT_MS }, { HZ_E4, BEAT_MS },
  { HZ_D4, BEAT_MS + BEAT_MS / 2U }, { HZ_C4, BEAT_MS / 2U }, { HZ_C4, 2U * BEAT_MS },
};

/* Bach, Minuet in G (opening, public domain) — 300 ms per quarter */
static const struct note_entry minuet_g[] = {
  { HZ_D5, 2U * BEAT_MS }, { HZ_G4, BEAT_MS }, { HZ_A4, BEAT_MS }, { HZ_B4, BEAT_MS },
  { HZ_C5, BEAT_MS }, { HZ_D5, 2U * BEAT_MS }, { HZ_G4, BEAT_MS }, { HZ_G4, BEAT_MS },
  { HZ_E5, 2U * BEAT_MS }, { HZ_C5, BEAT_MS }, { HZ_D5, BEAT_MS }, { HZ_E5, BEAT_MS },
  { HZ_F5, BEAT_MS }, { HZ_G5, 2U * BEAT_MS }, { HZ_G4, BEAT_MS }, { HZ_G4, BEAT_MS },
  { HZ_C5, BEAT_MS }, { HZ_D5, BEAT_MS }, { HZ_C5, BEAT_MS }, { HZ_B4, BEAT_MS },
  { HZ_A4, BEAT_MS }, { HZ_B4, BEAT_MS }, { HZ_C5, BEAT_MS }, { HZ_A4, BEAT_MS },
  { HZ_B4, BEAT_MS }, { HZ_A4, BEAT_MS }, { HZ_G4, BEAT_MS }, { HZ_F4, BEAT_MS },
  { HZ_G4, 4U * BEAT_MS },
};

/* Jingle Bells chorus excerpt (public domain) */
static const struct note_entry jingle_bells[] = {
  { HZ_E5, BEAT_MS }, { HZ_E5, BEAT_MS }, { HZ_E5, 2U * BEAT_MS },
  { HZ_E5, BEAT_MS }, { HZ_E5, BEAT_MS }, { HZ_E5, 2U * BEAT_MS },
  { HZ_E5, BEAT_MS }, { HZ_G5, BEAT_MS },
  { HZ_C5, BEAT_MS + BEAT_MS / 2U }, { HZ_D5, BEAT_MS / 2U },
  { HZ_E5, 4U * BEAT_MS },
  { HZ_F5, BEAT_MS }, { HZ_F5, BEAT_MS },
  { HZ_F5, BEAT_MS + BEAT_MS / 2U }, { HZ_F5, BEAT_MS / 2U },
  { HZ_F5, BEAT_MS }, { HZ_E5, BEAT_MS },
  { HZ_E5, BEAT_MS }, { HZ_E5, BEAT_MS / 2U }, { HZ_E5, BEAT_MS / 2U },
  { HZ_G5, BEAT_MS }, { HZ_G5, BEAT_MS }, { HZ_F5, BEAT_MS }, { HZ_D5, BEAT_MS },
  { HZ_C5, 4U * BEAT_MS },
};

struct song_slot {
  const struct note_entry *notes;
  size_t note_count;
};

static const struct song_slot playlist[] = {
  { ode_to_joy, sizeof(ode_to_joy) / sizeof(ode_to_joy[0]) },
  { minuet_g, sizeof(minuet_g) / sizeof(minuet_g[0]) },
  { jingle_bells, sizeof(jingle_bells) / sizeof(jingle_bells[0]) },
};

static const int16_t sine_table[SINE_TABLE_LEN] = {
  0, 3211, 6392, 9511, 12539, 15446, 18204, 20787, 23169, 25329, 27244, 28897,
  30272, 31356, 32137, 32609, 32767, 32609, 32137, 31356, 30272, 28897, 27244,
  25329, 23169, 20787, 18204, 15446, 12539, 9511, 6392, 3211, 0, -3212, -6393,
  -9512, -12540, -15447, -18205, -20788, -23170, -25330, -27245, -28898, -30273,
  -31357, -32138, -32610, -32767, -32610, -32138, -31357, -30273, -28898, -27245,
  -25330, -23170, -20788, -18205, -15447, -12540, -9512, -6393, -3212,
};

static uint32_t ms_to_samples(uint16_t ms)
{
  return ((uint32_t)ms * (uint32_t)FRAME_CLK_HZ) / 1000U;
}

static uint32_t hz_to_phase_inc(uint16_t hz)
{
  if (hz == 0U) {
    return 0U;
  }

  return (uint32_t)(((uint64_t)hz * (uint64_t)UINT32_MAX)
                    / (uint64_t)FRAME_CLK_HZ);
}

struct synth_ctx {
  size_t song_idx;
  size_t note_idx;
  uint32_t note_remaining;
  uint32_t gap_remaining;
  uint32_t phase;
  uint32_t phase_inc;
  uint16_t cur_hz;
  uint32_t attack_len;
  uint32_t release_len;
  uint32_t note_pos;
};

static struct synth_ctx ctx;
static bool done;

static void start_note(uint16_t hz, uint16_t dur_ms)
{
  ctx.cur_hz = hz;
  ctx.note_remaining = ms_to_samples(dur_ms);
  ctx.note_pos = 0U;
  ctx.phase = 0U;
  ctx.phase_inc = hz_to_phase_inc(hz);
  ctx.attack_len = ms_to_samples(5U);
  ctx.release_len = ms_to_samples(40U);
  if (ctx.release_len > ctx.note_remaining / 4U) {
    ctx.release_len = ctx.note_remaining / 4U;
  }
}

static void start_song_gap(void)
{
  ctx.gap_remaining = ms_to_samples(SONG_GAP_MS);
  ctx.note_remaining = 0U;
}

static void advance_note(void)
{
  const struct song_slot *slot = &playlist[ctx.song_idx];

  if (ctx.note_idx >= slot->note_count) {
    ctx.song_idx++;
    if (ctx.song_idx >= sizeof(playlist) / sizeof(playlist[0])) {
#if PLAYBACK_LOOP
      /* loopback mode: restart from the first song. */
      ctx.song_idx = 0U;
#else
      /* one-shot mode: played the whole playlist once -> stop. */
      done = true;
      ctx.note_remaining = 0U;
      ctx.gap_remaining = 0U;
      return;
#endif
    }
    ctx.note_idx = 0U;
    start_song_gap();
    return;
  }

  const struct note_entry *n = &slot->notes[ctx.note_idx++];

  start_note(n->hz, n->dur_ms);
}

static int16_t next_sample(void)
{
  if (done) {
    return 0;
  }

  if (ctx.gap_remaining > 0U) {
    ctx.gap_remaining--;
    if (ctx.gap_remaining == 0U) {
      advance_note();
    }
    return 0;
  }

  if (ctx.note_remaining == 0U) {
    advance_note();
    if (done) {
      return 0;
    }
    return next_sample();
  }

  ctx.note_remaining--;
  ctx.note_pos++;

  if (ctx.cur_hz == 0U) {
    return 0;
  }

  uint32_t idx = (ctx.phase >> 26) & (SINE_TABLE_LEN - 1U);

  ctx.phase += ctx.phase_inc;

  int32_t s = sine_table[idx];
  uint32_t env_q15 = 32767U;

  if (ctx.note_pos < ctx.attack_len && ctx.attack_len > 0U) {
    env_q15 = (32767U * ctx.note_pos) / ctx.attack_len;
  } else if (ctx.note_remaining < ctx.release_len && ctx.release_len > 0U) {
    env_q15 = (32767U * ctx.note_remaining) / ctx.release_len;
  }

  return (int16_t)((s * (int32_t)env_q15) / 32767);
}

void audio_init(void)
{
  memset(&ctx, 0, sizeof(ctx));
  done = false;
  advance_note();
}

const char *audio_source_name(void)
{
  return "short_songs";
}

bool audio_is_done(void)
{
  return done;
}

unsigned audio_fill_mono(int16_t *dest, unsigned n)
{
  for (unsigned i = 0U; i < n; i++) {
    dest[i] = next_sample();
  }

  return n;
}
