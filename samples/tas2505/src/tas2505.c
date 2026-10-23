/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * TAS2505 codec control over I2C.
 *
 * Sequencing follows TI SLAA557 / SLAU472C:
 *   1. SW reset
 *   2. Power up reference + LDO
 *   3. Program PLL/NDAC/MDAC/DOSR for the requested fs
 *   4. Audio interface format and DAC setup and unmute
 *   5. Route to mixer/speaker driver
 */

#include "tas2505.h"

#include <errno.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(tas2505, LOG_LEVEL_INF);

static uint8_t cur_page = 0xFF;

#define PLL_CLK_MIN_HZ  80000000U
#define PLL_CLK_MAX_HZ 110000000U

/**************************************************************************
* Low-level register access
**************************************************************************/
static int tas2505_select_page(const struct device *i2c, uint8_t page)
{
  if (page == cur_page) {
    return 0;
  }

  /* Page 0, register 0 is the page select register */
  uint8_t buf[2] = { 0x00, page };
  int ret = i2c_write(i2c, buf, sizeof(buf), TAS2505_I2C_ADDR);
  if (ret == 0) {
    cur_page = page;
  }
  return ret;
}

static int tas2505_write(const struct device *i2c, uint16_t reg, uint8_t val)
{
  int ret = tas2505_select_page(i2c, TAS2505_REG_PAGE(reg));
  if (ret < 0) {
    return ret;
  }

  uint8_t buf[2] = { TAS2505_REG_OFFSET(reg), val };
  ret = i2c_write(i2c, buf, sizeof(buf), TAS2505_I2C_ADDR);
  if (ret < 0) {
    LOG_ERR("I2C write reg=0x%04x val=0x%02x ret=%d", reg, val, ret);
  }
  return ret;
}

__maybe_unused static int tas2505_read(const struct device *i2c, uint16_t reg, uint8_t *out)
{
  int ret = tas2505_select_page(i2c, TAS2505_REG_PAGE(reg));
  if (ret < 0) {
    return ret;
  }

  uint8_t off = TAS2505_REG_OFFSET(reg);
  return i2c_write_read(i2c, TAS2505_I2C_ADDR, &off, 1, out, 1);
}

/**************************************************************************
* Convenience for (reg, val) initialization tables.
**************************************************************************/
struct reg_seq {
  uint16_t reg;
  uint8_t val;
};

static int tas2505_apply_seq(const struct device *i2c,
                             const struct reg_seq *seq, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    int ret = tas2505_write(i2c, seq[i].reg, seq[i].val);
    if (ret < 0) {
      return ret;
    }
  }
  return 0;
}

/**************************************************************************
* PLL / DAC clock-tree dividers
**************************************************************************/
struct tas2505_rate_divs {
  uint8_t  pll_p;
  uint8_t  pll_r;
  uint8_t  pll_j;
  uint16_t pll_d;
  uint8_t  ndac;
  uint8_t  mdac;
  uint16_t dosr;
};

/*
 * Hand-tuned for MCLK = 19.2 MHz (xG27 EXPCLK = HFRCODPLL/prescaler = 76.8/4).
 * PLL_CLK = MCLK * R * (J + D/10000) / P.  Targeted PLL_CLK chosen so that
 * NDAC * MDAC * DOSR * fs == PLL_CLK and PLL_CLK lies in [80, 110] MHz.
 *
 * If you change MCLK, recompute these or add a new table entry.
 */
static int tas2505_clk_get_divs(uint32_t mclk_hz, uint32_t fs,
                                struct tas2505_rate_divs *desired_rate_divs)
{
  if (mclk_hz == 19200000U) {
    switch (fs) {
      case 48000U:
        *desired_rate_divs = (struct tas2505_rate_divs){ 1, 1, 4, 4800, 2, 7, 128 };
        return 0;
      case 44100U:
        *desired_rate_divs = (struct tas2505_rate_divs){ 1, 1, 4, 4100, 5, 3, 128 };
        return 0;
      case 16000U:
        *desired_rate_divs = (struct tas2505_rate_divs){ 1, 1, 4, 2667, 5, 8, 128 };
        return 0;
      case 8000U:
        *desired_rate_divs = (struct tas2505_rate_divs){ 1, 1, 4, 2667, 10, 8, 128 };
        return 0;
      default:
        LOG_ERR("fs=%u Hz: not in coefficient table", fs);
        return -ENOTSUP;
    }
  } else {
    LOG_ERR("MCLK=%u Hz: no precomputed table; recompute J/D and "
            "NDAC/MDAC/DOSR for this rate", mclk_hz);
    return -ENOTSUP;
  }
}

/**************************************************************************
* Init sequence
**************************************************************************/
int tas2505_init(const struct device *i2c, const struct tas2505_init_params *p)
{
  int ret;
  struct tas2505_rate_divs rate_divs;
  uint8_t iface1;
  const uint8_t clkmux = (uint8_t)(TAS2505_PLL_CLKIN_MCLK | TAS2505_CODEC_CLKIN_PLL);
  uint8_t pllpr;

  if (!device_is_ready(i2c)) {
    LOG_ERR("I2C device not ready");
    return -ENODEV;
  }
  if (p == NULL || (p->word_bits != 16 && p->word_bits != 32)) {
    return -EINVAL;
  }

  ret = tas2505_clk_get_divs(p->mclk_hz, p->sample_rate, &rate_divs);
  if (ret < 0) {
    return ret;
  }

  cur_page = 0xFF;

  /* (1) Software reset.  Self-clears, but waiting 1 ms is safe. */
  ret = tas2505_write(i2c, TAS2505_SW_RESET, 0x01);
  if (ret < 0) {
    return ret;
  }
  k_msleep(2);

  /* (2) Page 1: LDO 1.8 V, level shifters on (early, before PLL). */
  ret = tas2505_write(i2c, TAS2505_LDO_CTRL, 0x00);
  if (ret < 0) {
    return ret;
  }

  /* (3) Page 0: PRB #1, then PLL / codec clock mux. */
  pllpr = (uint8_t)(TAS2505_PWR_UP | ((rate_divs.pll_p & 0x07U) << 4)
                    | (rate_divs.pll_r & 0x0FU));
  const struct reg_seq clk_seq[] = {
    { TAS2505_DAC_PROCBLOCK, 0x01 },
    { TAS2505_CLKMUX, clkmux },
    { TAS2505_PLLPR, pllpr },
    { TAS2505_PLLJ, (uint8_t)(rate_divs.pll_j & 0x3FU) },
    { TAS2505_PLLD_MSB, (uint8_t)((rate_divs.pll_d >> 8) & 0x3F) },
    { TAS2505_PLLD_LSB, (uint8_t)(rate_divs.pll_d & 0xFF) },
  };

  ret = tas2505_apply_seq(i2c, clk_seq, ARRAY_SIZE(clk_seq));
  if (ret < 0) {
    return ret;
  }
  k_msleep(15);

  /* (4) Page 0: I2S interface format and DAC setup. */
  iface1 = (uint8_t)TAS2505_IFACE_I2S;
  switch (p->word_bits) {
    case 16:
      iface1 |= (uint8_t)TAS2505_WLEN_16;
      break;
    case 32:
      iface1 |= (uint8_t)TAS2505_WLEN_32;
      break;
  }
  if (!p->mcu_is_master) {
    iface1 |= (uint8_t)(TAS2505_BCLK_OUT | TAS2505_WCLK_OUT);
  }

  const struct reg_seq iface_dac_clk[] = {
    { TAS2505_IFACE1, iface1 },
    { TAS2505_IFACE2, 0x00 },
    { TAS2505_NDAC, (uint8_t)(TAS2505_PWR_UP | (rate_divs.ndac & 0x7FU)) },
    { TAS2505_MDAC, (uint8_t)(TAS2505_PWR_UP | (rate_divs.mdac & 0x7FU)) },
    { TAS2505_DOSR_MSB, (uint8_t)((rate_divs.dosr >> 8) & 0x03) },
    { TAS2505_DOSR_LSB, (uint8_t)(rate_divs.dosr & 0xFF) },
    { TAS2505_DACSETUP1, TAS2505_DACSETUP1_CLASSD_MONO },
    { TAS2505_DACSETUP2, TAS2505_DACSETUP2_CLASSD_MONO },
    { TAS2505_DACVOL, 0x00 },
  };

  ret = tas2505_apply_seq(i2c, iface_dac_clk, ARRAY_SIZE(iface_dac_clk));
  if (ret < 0) {
    return ret;
  }

  /* (5) Analog reference, Class-D speaker path.  */
  const struct reg_seq analog_out[] = {
    { TAS2505_REF_POR_LDO_BGAP, 0x10 },
    { TAS2505_COMMON_MODE, 0x00 },
    { TAS2505_PLAYBACKCONF1, 0x00 },
    { TAS2505_SPK_VOL_DRV, 0x14 },      /* -10dB */
    { TAS2505_SPK_VOL_AMP, 0x10 },
    { TAS2505_SPK_OCP, 0x00 },
    { TAS2505_SPK_AMP_CTRL, TAS2505_SPK_DRV_ENABLE },
  };

  ret = tas2505_apply_seq(i2c, analog_out, ARRAY_SIZE(analog_out));
  if (ret < 0) {
    return ret;
  }

  LOG_INF("TAS2505 init OK: MCLK=%u fs=%u w%u PLL=%u.%04u N/M/DOSR=%u/%u/%u",
          p->mclk_hz, p->sample_rate, p->word_bits,
          rate_divs.pll_j, rate_divs.pll_d,
          rate_divs.ndac, rate_divs.mdac, rate_divs.dosr);
  return 0;
}

/**************************************************************************
* Runtime control
**************************************************************************/
int tas2505_unmute(const struct device *i2c)
{
  return tas2505_write(i2c, TAS2505_DACSETUP2, TAS2505_DAC_UNMUTE);
}

int tas2505_mute(const struct device *i2c)
{
  return tas2505_write(i2c, TAS2505_DACSETUP2, TAS2505_DAC_MUTE);
}

int tas2505_set_dac_volume(const struct device *i2c, int8_t db_x2)
{
  if (db_x2 < -127 || db_x2 > 48) {
    return -EINVAL;
  }
  return tas2505_write(i2c, TAS2505_DACVOL, (uint8_t)db_x2);
}

int tas2505_set_spk_drv_volume(const struct device *i2c, uint8_t code)
{
  if (code > 117) {
    return -EINVAL;
  }
  return tas2505_write(i2c, TAS2505_SPK_VOL_DRV, code);
}

int tas2505_set_spk_amp_gain(const struct device *i2c, uint8_t code)
{
  if (code > 3) {
    return -EINVAL;
  }
  return tas2505_write(i2c, TAS2505_SPK_VOL_AMP, (uint8_t)(code << 4));
}
