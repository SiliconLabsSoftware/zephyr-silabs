/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * TAS2505 codec register map and public API.
 *
 * Reference:
 *   - TAS2505 datasheet (SLAS561)
 *   - TAS2505 application reference guide (SLAA557)
 *   - TAS2505 user guide (SLAU472C)
 */

#ifndef TAS2505_H
#define TAS2505_H

#include <stdint.h>
#include <zephyr/device.h>

/* Default 7-bit I2C address */
#define TAS2505_I2C_ADDR 0x18

/* Encode (page, offset) into a single 16-bit register handle.  The driver
 * splits page from offset on every transaction and writes Page Select
 * (page-0/reg-0) only when the page actually changes.
 */
#define TAS2505_REG(page, reg) ((page * 128) + reg)
#define TAS2505_REG_PAGE(r)    (((r) >> 7) & 0xFF)
#define TAS2505_REG_OFFSET(r)  ((r) & 0x7F)

/* Page 0 -- clocks, interface, DAC */
#define TAS2505_PAGECTL              TAS2505_REG(0, 0)
#define TAS2505_SW_RESET             TAS2505_REG(0, 1)
#define TAS2505_CLKMUX               TAS2505_REG(0, 4)
#define TAS2505_PLLPR                TAS2505_REG(0, 5)
#define TAS2505_PLLJ                 TAS2505_REG(0, 6)
#define TAS2505_PLLD_MSB             TAS2505_REG(0, 7)
#define TAS2505_PLLD_LSB             TAS2505_REG(0, 8)
#define TAS2505_NDAC                 TAS2505_REG(0, 11)
#define TAS2505_MDAC                 TAS2505_REG(0, 12)
#define TAS2505_DOSR_MSB             TAS2505_REG(0, 13)
#define TAS2505_DOSR_LSB             TAS2505_REG(0, 14)
#define TAS2505_CDIV_CLKIN           TAS2505_REG(0, 25)
#define TAS2505_CLKOUT_DIV           TAS2505_REG(0, 26)
#define TAS2505_IFACE1               TAS2505_REG(0, 27)
#define TAS2505_IFACE2               TAS2505_REG(0, 28)
#define TAS2505_IFACE3               TAS2505_REG(0, 29)
#define TAS2505_BCLKNDIV             TAS2505_REG(0, 30)
#define TAS2505_DACFLAG1             TAS2505_REG(0, 37)
#define TAS2505_DACFLAG2             TAS2505_REG(0, 38)
#define TAS2505_STICKYFLAG1          TAS2505_REG(0, 42)
#define TAS2505_INTFLAG1             TAS2505_REG(0, 43)
#define TAS2505_STICKYFLAG2          TAS2505_REG(0, 44)
#define TAS2505_INTFLAG2             TAS2505_REG(0, 46)
#define TAS2505_DAC_PROCBLOCK        TAS2505_REG(0, 60)
#define TAS2505_DACSETUP1            TAS2505_REG(0, 63)
#define TAS2505_DACSETUP2            TAS2505_REG(0, 64)
#define TAS2505_DACVOL               TAS2505_REG(0, 65)

/* Page 1 -- analog, LDO, speaker amp */
#define TAS2505_REF_POR_LDO_BGAP     TAS2505_REG(1, 1)
#define TAS2505_LDO_CTRL             TAS2505_REG(1, 2)
#define TAS2505_PLAYBACKCONF1        TAS2505_REG(1, 3)
#define TAS2505_OUTPUT_DRV_PWR       TAS2505_REG(1, 9)
#define TAS2505_COMMON_MODE          TAS2505_REG(1, 10)
#define TAS2505_HP_OUT_DRV           TAS2505_REG(1, 12)
#define TAS2505_HP_DRV_GAIN          TAS2505_REG(1, 16)
#define TAS2505_SPK_AMP_CTRL         TAS2505_REG(1, 45)
#define TAS2505_SPK_VOL_DRV          TAS2505_REG(1, 46)
#define TAS2505_SPK_VOL_AMP          TAS2505_REG(1, 48)
#define TAS2505_SPK_OCP              TAS2505_REG(1, 82)

/* Bit-field helpers */
/* CLKMUX (P0/R4) */
#define TAS2505_PLL_CLKIN_MCLK       0x00
#define TAS2505_PLL_CLKIN_BCLK       0x04
#define TAS2505_PLL_CLKIN_GPIO       0x08
#define TAS2505_PLL_CLKIN_DIN        0x0C
#define TAS2505_CODEC_CLKIN_MCLK     0x00
#define TAS2505_CODEC_CLKIN_BCLK     0x01
#define TAS2505_CODEC_CLKIN_GPIO     0x02
#define TAS2505_CODEC_CLKIN_PLL      0x03

/* PLL/NDAC/MDAC power bit (D7=1 to power up) */
#define TAS2505_PWR_UP               0x80

/* IFACE1 (P0/R27) */
#define TAS2505_IFACE_I2S            0x00
#define TAS2505_IFACE_DSP            0x40
#define TAS2505_IFACE_RJF            0x80
#define TAS2505_IFACE_LJF            0xC0
#define TAS2505_WLEN_16              0x00
#define TAS2505_WLEN_20              0x10
#define TAS2505_WLEN_24              0x20
#define TAS2505_WLEN_32              0x30
#define TAS2505_BCLK_OUT             0x08   /* TAS2505 drives BCLK (BCLK_OUT) */
#define TAS2505_WCLK_OUT             0x04   /* TAS2505 drives WCLK (WCLK_OUT) */

/* DACSETUP1 (P0/R63): Class-D mono playback — LDAC only, RDAC data off */
#define TAS2505_DACSETUP1_CLASSD_MONO 0xB0

/* DACSETUP2 (P0/R64): L unmuted, R muted for mono Class-D path. */
#define TAS2505_DACSETUP2_CLASSD_MONO 0x04
#define TAS2505_DAC_MUTE              0x08
#define TAS2505_DAC_UNMUTE            TAS2505_DACSETUP2_CLASSD_MONO

/* SPK_AMP_CTRL (P1/R45): D1=power on speaker driver */
#define TAS2505_SPK_DRV_ENABLE       0x02

struct tas2505_init_params {
  uint32_t mclk_hz;          /* MCLK feeding PLL_CLKIN, e.g. 12800000 */
  uint32_t sample_rate;      /* I2S frame clock target, e.g. 48000 */
  uint8_t  word_bits;        /* 16 or 32 */
  bool     mcu_is_master;    /* true: MCU drives BCLK+WCLK (typical) */
};

int tas2505_init(const struct device *i2c_dev, const struct tas2505_init_params *p);
int tas2505_unmute(const struct device *i2c_dev);
int tas2505_mute(const struct device *i2c_dev);
int tas2505_set_dac_volume(const struct device *i2c_dev, int8_t db_x2);
int tas2505_set_spk_drv_volume(const struct device *i2c_dev, uint8_t code);
int tas2505_set_spk_amp_gain(const struct device *i2c_dev, uint8_t code);

#endif /* TAS2505_H */
