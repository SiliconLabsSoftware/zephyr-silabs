/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Plays audio on USART0 I2S for TAS2505 / I2S DAC.
 *
 * Build-time audio source (CMake AUDIO_SOURCE):
 *   pcm         - embedded song_pcm.c
 *   short_songs - runtime public-domain melodies (FRAME_CLK_HZ, WORD_SIZE_BITS)
 *
 * Build-time channel routing (CMake CHANNEL_MODE -> CHANNEL_MODE_ID):
 *   mono_left  (1) - audio in L slot, R silent (channels=1 + DMASPLIT +
 *                    silabs,mono-tx-slot = "left" via boards/mono_left.overlay)
 *   mono_right (2) - audio in R slot, L silent (channels=1 + driver DMASPLIT;
 *                    default silabs,mono-tx-slot = "right")

 *   stereo     (3) - interleaved L+R (native stereo source or duplicate mono)
 */

#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/i2s.h>
#include <zephyr/logging/log.h>

#include "audio.h"

#if TAS2505_BOARD
#include "tas2505.h"
#endif

#define CODEC_I2C_NODE DT_ALIAS(codec_tas2505)

#if DT_HAS_COMPAT_STATUS_OKAY(silabs_series_clock_clkout)
/*
 * MCLK comes from a CMU CLKOUT (silabs,series-clock-clkout) sourced from
 * EXPORTCLK (HFEXPCLK = SYSCLK) divided by clock-div. SYSCLK = HFRCODPLL
 * default 76.8 MHz on xG27, so clock-div = 4 -> 19.2 MHz.
 */
#define TAS2505_MCO_NODE  DT_COMPAT_GET_ANY_STATUS_OKAY(silabs_series_clock_clkout)
#define TAS2505_SYSCLK_HZ 76800000U
#define CODEC_MCLK_HZ     (TAS2505_SYSCLK_HZ / (uint32_t)DT_PROP_OR(TAS2505_MCO_NODE, clock_div, 1))
#else
#define CODEC_MCLK_HZ 19200000U
#endif

LOG_MODULE_REGISTER(tas2505_sample, LOG_LEVEL_INF);

#ifndef FRAME_CLK_HZ
#define FRAME_CLK_HZ 16000
#endif

#ifndef WORD_SIZE_BITS
#define WORD_SIZE_BITS 16
#endif

/* Channel routing IDs -- keep in sync with CMakeLists.txt. */
#define CHANNEL_MODE_MONO_LEFT  1
#define CHANNEL_MODE_MONO_RIGHT 2
#define CHANNEL_MODE_STEREO     3

#ifndef CHANNEL_MODE_ID
#define CHANNEL_MODE_ID  CHANNEL_MODE_MONO_RIGHT
#endif
#ifndef CHANNEL_MODE_NAME
#define CHANNEL_MODE_NAME "mono_right"
#endif

/*
 * PLAYBACK_LOOP / PLAYBACK_MODE_NAME come from CMake (PLAYBACK_MODE):
 *   PLAYBACK_LOOP=0 -> "one_shot": play once, drain, gate BCLK/LRCLK.
 *   PLAYBACK_LOOP=1 -> "loopback": play forever, no drain/gating.
 */
#ifndef PLAYBACK_LOOP
#define PLAYBACK_LOOP 0
#endif
#ifndef PLAYBACK_MODE_NAME
#define PLAYBACK_MODE_NAME "one_shot"
#endif

#if WORD_SIZE_BITS == 16
typedef int16_t sample_t;
#define SAMPLE_EXPAND(m) ((sample_t)(m))
#elif WORD_SIZE_BITS == 32
typedef int32_t sample_t;
/*
 * The EFR32 USART I2S driver runs in W32D16 (32-bit slot, 16-bit data); the
 * driver comment in i2s_silabs_efr32_usart.c is explicit:
 *
 *   W32D16: int32_t [L0, R0, L1, R1, ...]    -- audio in low 16 bits
 *
 * So we put the int16 mono sample into the LOW 16 bits of the int32 slot
 * and leave the upper 16 bits as zero. The cast chain int16 -> uint16 ->
 * uint32 keeps the sign-magnitude bits intact without sign-extending into
 * the upper half (which the USART would otherwise shift out as garbage).
 */
#define SAMPLE_EXPAND(m) ((sample_t)(uint32_t)(uint16_t)(int16_t)(m))
#else
#error "WORD_SIZE_BITS must be 16 or 32"
#endif

#define NUM_BLOCKS         8
#define SAMPLES_PER_BLOCK  256
#define PREROLL_BLOCKS     0
#define TAIL_SILENT_BLOCKS 0
#define BLOCK_FRAMES       SAMPLES_PER_BLOCK
#define DRAIN_TIMEOUT_MS   2000U

#if CHANNEL_MODE_ID == CHANNEL_MODE_MONO_LEFT || CHANNEL_MODE_ID == CHANNEL_MODE_MONO_RIGHT
/*
 * mono_left / mono_right: i2s_configure(channels=1) enables USART
 * I2SCTRL.DMASPLIT. App buffer is [M0, M1, ...]; driver LDMA feeds silence
 * on one slot and samples on the other. Slot pick is via silabs,mono-tx-slot
 * (mono_left adds boards/mono_left.overlay; mono_right uses the DT default).
 * Half the TX mem_slab RAM vs stereo interleave.
 */
#define I2S_CHANNELS 1U
#define BLOCK_SIZE   (SAMPLES_PER_BLOCK * (int)sizeof(sample_t))
#else
#define I2S_CHANNELS 2U
#define BLOCK_SIZE   (SAMPLES_PER_BLOCK * 2 * (int)sizeof(sample_t))
#endif

#define I2S_OPTIONS (I2S_OPT_FRAME_CLK_CONTROLLER | I2S_OPT_BIT_CLK_CONTROLLER)

K_MEM_SLAB_DEFINE(tx_slab, WB_UP(BLOCK_SIZE), NUM_BLOCKS, WB_UP(32));

#if CHANNEL_MODE_ID == CHANNEL_MODE_MONO_LEFT || CHANNEL_MODE_ID == CHANNEL_MODE_MONO_RIGHT
static void fill_block_mono(sample_t *tx, unsigned n)
{
#if WORD_SIZE_BITS == 16
  audio_fill_mono(tx, n);
#else
  int16_t mono[SAMPLES_PER_BLOCK];

  audio_fill_mono(mono, n);
  for (unsigned i = 0; i < n; i++) {
    tx[i] = SAMPLE_EXPAND(mono[i]);
  }
#endif
}
#define fill_block(tx, n) fill_block_mono((tx), (n))
#else
/*
 * fill_block_stereo() -- fill one TX mem_slab block (n frames).
 *
 * Pulls n mono samples via audio_fill_mono(), then writes interleaved
 * L/R into *tx per CHANNEL_MODE_ID. i2s_configure uses channels=2 here;
 * every LRCLK frame on the wire has two slots. CHANNEL_MODE_STEREO still
 * duplicates mono to both slots until a true stereo source is added.
 */
static void fill_block_stereo(sample_t *tx, unsigned n)
{
  int16_t mono[SAMPLES_PER_BLOCK];

  audio_fill_mono(mono, n);

  for (unsigned i = 0; i < n; i++) {
    sample_t ex = SAMPLE_EXPAND(mono[i]);

    tx[2 * i]     = ex;
    tx[2 * i + 1] = ex;
  }
}
#define fill_block(tx, n) fill_block_stereo((tx), (n))
#endif

int main(void)
{
  void *tx_block;
  struct i2s_config i2s_cfg;
  int ret;
  const struct device *dev = DEVICE_DT_GET(DT_ALIAS(i2s_tx));

  audio_init();

  LOG_INF("sample start board=%s audio=%s channels=%s i2s_ch=%u playback=%s "
          "FRAME_CLK_HZ=%d WORD_SIZE=%d block=%u",
          CONFIG_BOARD_TARGET, audio_source_name(), CHANNEL_MODE_NAME,
          (unsigned int)I2S_CHANNELS, PLAYBACK_MODE_NAME, FRAME_CLK_HZ,
          WORD_SIZE_BITS, (unsigned int)BLOCK_SIZE);

  if (!device_is_ready(dev)) {
    LOG_ERR("I2S device not ready");
    return -ENODEV;
  }

  i2s_cfg.word_size = WORD_SIZE_BITS;
  i2s_cfg.channels = I2S_CHANNELS;
  i2s_cfg.format = I2S_FMT_DATA_FORMAT_I2S;
  i2s_cfg.frame_clk_freq = FRAME_CLK_HZ;
  i2s_cfg.block_size = BLOCK_SIZE;
  i2s_cfg.timeout = 2000;
  i2s_cfg.options = I2S_OPTIONS;
  i2s_cfg.mem_slab = &tx_slab;

  ret = i2s_configure(dev, I2S_DIR_TX, &i2s_cfg);
  if (ret < 0) {
    LOG_ERR("i2s_configure failed: %d", ret);
    return ret;
  }
  LOG_INF("i2s_configure ok");

#if TAS2505_BOARD
  const struct device *codec_i2c = DEVICE_DT_GET(CODEC_I2C_NODE);
  const struct tas2505_init_params codec_p = {
    .mclk_hz = CODEC_MCLK_HZ,
    .sample_rate = FRAME_CLK_HZ,
    .word_bits = WORD_SIZE_BITS,
    .mcu_is_master = true,
  };

  LOG_INF("TAS2505 MCLK from DT: %u Hz", CODEC_MCLK_HZ);
  ret = tas2505_init(codec_i2c, &codec_p);
  if (ret < 0) {
    LOG_ERR("tas2505_init failed: %d", ret);
    return ret;
  }
#endif

  for (unsigned int i = 0U; i < PREROLL_BLOCKS; i++) {
    ret = k_mem_slab_alloc(&tx_slab, &tx_block, K_FOREVER);
    if (ret < 0) {
      LOG_ERR("slab alloc (pre-roll) failed: %d", ret);
      return ret;
    }
    memset(tx_block, 0, BLOCK_SIZE);
    ret = i2s_write(dev, tx_block, BLOCK_SIZE);
    if (ret < 0) {
      LOG_ERR("i2s_write (pre-roll) failed: %d", ret);
      return ret;
    }
  }
  LOG_INF("pre-roll queued: %u silent blocks", (unsigned int)PREROLL_BLOCKS);

  LOG_INF("I2S START @ %d Hz", FRAME_CLK_HZ);
  ret = i2s_trigger(dev, I2S_DIR_TX, I2S_TRIGGER_START);
  if (ret < 0) {
    LOG_ERR("i2s_trigger START failed: %d", ret);
    return ret;
  }

#if PLAYBACK_LOOP
  /*
   * Loopback mode: stream forever; audio_is_done() is hard-wired to
   * false so the source itself wraps back to the start of the clip /
   * playlist.
   */
  while (1) {
    ret = k_mem_slab_alloc(&tx_slab, &tx_block, K_FOREVER);
    if (ret < 0) {
      LOG_ERR("slab alloc failed: %d", ret);
      return ret;
    }

    fill_block((sample_t *)tx_block, SAMPLES_PER_BLOCK);

    ret = i2s_write(dev, tx_block, BLOCK_SIZE);
    if (ret < 0) {
      LOG_ERR("i2s_write failed: %d", ret);
      return ret;
    }
  }
#else
  /* One-shot playback: stream blocks until the audio source signals done. */
  while (!audio_is_done()) {
    ret = k_mem_slab_alloc(&tx_slab, &tx_block, K_FOREVER);
    if (ret < 0) {
      LOG_ERR("slab alloc failed: %d", ret);
      return ret;
    }

    fill_block((sample_t *)tx_block, SAMPLES_PER_BLOCK);

    ret = i2s_write(dev, tx_block, BLOCK_SIZE);
    if (ret < 0) {
      LOG_ERR("i2s_write failed: %d", ret);
      return ret;
    }
  }

  LOG_INF("audio source reports done; queuing %u silent tail blocks",
          (unsigned int)TAIL_SILENT_BLOCKS);

  for (unsigned int i = 0U; i < TAIL_SILENT_BLOCKS; i++) {
    ret = k_mem_slab_alloc(&tx_slab, &tx_block, K_FOREVER);
    if (ret < 0) {
      LOG_ERR("slab alloc (tail) failed: %d", ret);
      return ret;
    }
    memset(tx_block, 0, BLOCK_SIZE);
    ret = i2s_write(dev, tx_block, BLOCK_SIZE);
    if (ret < 0) {
      LOG_ERR("i2s_write (tail) failed: %d", ret);
      return ret;
    }
  }

  ret = i2s_trigger(dev, I2S_DIR_TX, I2S_TRIGGER_DRAIN);
  if (ret < 0) {
    LOG_ERR("i2s_trigger DRAIN failed: %d", ret);
    return ret;
  }

  const uint32_t drain_ms_est = (uint32_t)((NUM_BLOCKS + TAIL_SILENT_BLOCKS)
                                           * BLOCK_FRAMES * 1000ULL
                                           / (uint32_t)FRAME_CLK_HZ) + 100U;
  const uint32_t drain_ms = drain_ms_est < DRAIN_TIMEOUT_MS
                            ? drain_ms_est : DRAIN_TIMEOUT_MS;

  LOG_INF("draining (~%u ms)...", (unsigned int)drain_ms);
  k_sleep(K_MSEC(drain_ms));

  struct i2s_config i2s_off = { 0 };

  ret = i2s_configure(dev, I2S_DIR_TX, &i2s_off);
  if (ret < 0) {
    LOG_ERR("i2s_configure(off) failed: %d", ret);
    return ret;
  }
  LOG_INF("I2S stopped; BCLK/LRCLK gated. Probe pins to confirm: "
          "DIN/BCLK/LRCLK should be idle.");

  while (1) {
    k_sleep(K_FOREVER);
  }
#endif

  return 0;
}
