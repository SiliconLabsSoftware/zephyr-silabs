/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/irq.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/sys_io.h>
#include <zephyr/device.h>
#include <zephyr/drivers/dma.h>
#include <zephyr/sys/mem_blocks.h>
#include <zephyr/drivers/clock_control.h>
#include <zephyr/logging/log.h>
#include <zephyr/types.h>
#include "rsi_rom_udma.h"
#include "rsi_rom_udma_wrapper.h"
#include "rsi_udma.h"
#include "sl_status.h"

#define DT_DRV_COMPAT                    silabs_siwx917_dma
#define DMA_MAX_TRANSFER_COUNT           1024
#define DMA_CH_PRIORITY_HIGH             1
#define DMA_CH_PRIORITY_LOW              0
#define UDMA_ADDR_INC_NONE               0x03
#define UDMA_MODE_PER_ALT_SCATTER_GATHER 0x07

LOG_MODULE_REGISTER(si91x_dma, CONFIG_DMA_LOG_LEVEL);

enum {
	TRANSFER_MEM_TO_MEM,
	TRANSFER_TO_OR_FROM_PER,
};

struct dma_siwx917_config {
	UDMA0_Type *reg;                 /* UDMA register base address */
	uint8_t channels;                /* UDMA channel count */
	uint8_t irq_number;              /* IRQ number */
	RSI_UDMA_DESC_T *sram_desc_addr; /* SRAM Address for UDMA Descriptor Storage */
	const struct device *clock_dev;
	clock_control_subsys_t clock_subsys;
	void (*irq_configure)(void);     /* IRQ configure function */
};

struct dma_siwx917_data {
	UDMA_Channel_Info *chan_info; /* TODO: This structure is currently utilized to update
				       * the DMA transfer information and pass it to the ROM API
				       * within `siwx917_dma_isr`. In the future, it can be
				       * replaced with a local structure tailored specifically
				       * to this driver, which will be implemented once support
				       * for RAM-executing ISRs is available.
				       */
	uint32_t *sg_desc_addr_info;  /* Pointer to table which stores scatter-gather descriptor
				       * addresses for each channel
				       */
	dma_callback_t dma_callback;  /* User callback */
	void *cb_data;                /* User callback data */
	struct sys_mem_blocks *dma_desc_pool; /* Pointer to the memory pool for DMA descriptor */
	RSI_UDMA_DATACONTEXT_T udma_handle;   /* Buffer to store UDMA handle
					       * related information
					       */
};

static int siwx917_transfer_direction(uint32_t dir)
{
	if (dir == MEMORY_TO_MEMORY) {
		return TRANSFER_MEM_TO_MEM;
	}

	if (dir == MEMORY_TO_PERIPHERAL || dir == PERIPHERAL_TO_MEMORY) {
		return TRANSFER_TO_OR_FROM_PER;
	}

	return -EINVAL;
}

static int siwx917_data_width(uint32_t data_width)
{
	switch (data_width) {
	case 1:
		return SRC_SIZE_8;
	case 2:
		return SRC_SIZE_16;
	case 4:
		return SRC_SIZE_32;
	default:
		return -EINVAL;
	}
}

static bool siwx917_is_burst_length_valid(uint32_t blen)
{
	switch (blen / 8) {
	case 1:
		return true; /* 8-bit burst */
	default:
		return false;
	}
}

static int siwx917_addr_adjustment(uint32_t adjustment)
{
	switch (adjustment) {
	case 0:
		return 0; /* Addr Increment */
	case 2:
		return UDMA_ADDR_INC_NONE; /* No Address increment */
	default:
		return -EINVAL;
	}
}

/* Sets up the scatter-gather descriptor table for a DMA transfer */
static int siwx917_sg_fill_desc(RSI_UDMA_DESC_T *descs, const struct dma_config *config_zephyr)
{
	const struct dma_block_config *block_addr = config_zephyr->head_block;
	RSI_UDMA_CHA_CONFIG_DATA_T *cfg_917;

	for (int i = 0; i < config_zephyr->block_count; i++) {
		sys_write32((uint32_t)&descs[i].vsUDMAChaConfigData1, (mem_addr_t)&cfg_917);

		descs[i].pSrcEndAddr =
			(void *)(block_addr->source_address +
				 (block_addr->block_size - config_zephyr->source_data_size));
		descs[i].pDstEndAddr =
			(void *)(block_addr->dest_address +
				 (block_addr->block_size - config_zephyr->dest_data_size));


		cfg_917->srcSize = siwx917_data_width(config_zephyr->source_data_size);
		cfg_917->dstSize = siwx917_data_width(config_zephyr->dest_data_size);

		/* Calculate the number of DMA transfers required */
		if (block_addr->block_size / config_zephyr->source_data_size >
		    DMA_MAX_TRANSFER_COUNT) {
			return -EINVAL;
		}

		cfg_917->totalNumOfDMATrans =
			block_addr->block_size / config_zephyr->source_data_size - 1;

		/* Set the transfer type based on whether it is a peripheral request */
		if (siwx917_transfer_direction(config_zephyr->channel_direction) ==
		    TRANSFER_TO_OR_FROM_PER) {
			cfg_917->transferType = UDMA_MODE_PER_ALT_SCATTER_GATHER;
		} else {
			cfg_917->transferType = UDMA_MODE_MEM_ALT_SCATTER_GATHER;
		}

		cfg_917->rPower = ARBSIZE_1;

		if (siwx917_addr_adjustment(block_addr->source_addr_adj) < 0 ||
		    siwx917_addr_adjustment(block_addr->dest_addr_adj) < 0) {
			return -EINVAL;
		}

		if (siwx917_addr_adjustment(block_addr->source_addr_adj) == UDMA_ADDR_INC_NONE) {
			cfg_917->srcInc = UDMA_SRC_INC_NONE;
		} else {
			cfg_917->srcInc = siwx917_data_width(config_zephyr->source_data_size);
		}

		if (siwx917_addr_adjustment(block_addr->dest_addr_adj) == UDMA_ADDR_INC_NONE) {
			cfg_917->dstInc = UDMA_DST_INC_NONE;
		} else {
			cfg_917->dstInc = siwx917_data_width(config_zephyr->dest_data_size);
		}

		/* Move to the next block */
		block_addr = block_addr->next_block;
	}

	if (block_addr != NULL) {
		/* next_block address for last block must be null */
		return -EINVAL;
	}

	/* Set the transfer type for the last descriptor */
	switch (siwx917_transfer_direction(config_zephyr->channel_direction)) {
	case TRANSFER_TO_OR_FROM_PER:
		descs[config_zephyr->block_count - 1].vsUDMAChaConfigData1.transferType =
			UDMA_MODE_BASIC;
		break;
	case TRANSFER_MEM_TO_MEM:
		descs[config_zephyr->block_count - 1].vsUDMAChaConfigData1.transferType =
			UDMA_MODE_AUTO;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* Configure DMA for scatter-gather transfer */
static int siwx917_sg_config(const struct device *dev, RSI_UDMA_HANDLE_T udma_handle,
			     uint32_t channel, const struct dma_config *config)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	RSI_UDMA_DESC_T *sg_desc_base_addr = NULL;
	uint8_t transfer_type;
	int ret;

	ret = siwx917_transfer_direction(config->channel_direction);
	if (ret) {
		return -EINVAL;
	}
	transfer_type = ret ? UDMA_MODE_PER_SCATTER_GATHER : UDMA_MODE_MEM_SCATTER_GATHER;

	if (siwx917_data_width(config->source_data_size) < 0 ||
	    siwx917_data_width(config->dest_data_size) < 0) {
		return -EINVAL;
	}

	if (config->block_count > CONFIG_DMA_SILABS_SIWX917_SG_BUFFER_COUNT) {
		return -EINVAL;
	}

	/* Request start index for scatter-gather descriptor table */
	if (sys_mem_blocks_alloc_contiguous(data->dma_desc_pool, config->block_count,
					    (void **)&sg_desc_base_addr)) {
		return -EINVAL;
	}

	if (siwx917_sg_fill_desc(sg_desc_base_addr, config)) {
		return -EINVAL;
	}

	/* This channel information is used to distinguish scatter-gather transfers and
	 * free the allocated descriptors in sg_transfer_desc_block
	 */
	data->chan_info[channel].Cnt = config->block_count;
	data->sg_desc_addr_info[channel] = (uint32_t)sg_desc_base_addr;
	RSI_UDMA_InterruptClear(udma_handle, channel);
	RSI_UDMA_ErrorStatusClear(udma_handle);

	if (cfg->reg == UDMA0) {
		/* UDMA0 is accessible by both TA and M4, so an interrupt should be configured in
		 * the TA-M4 common register set to signal the TA when UDMA0 is actively in use.
		 */
		sys_write32((BIT(channel) | M4SS_UDMA_INTR_SEL), (mem_addr_t)&M4SS_UDMA_INTR_SEL);
	} else {
		sys_set_bit((mem_addr_t)&cfg->reg->UDMA_INTR_MASK_REG, channel);
	}

	sys_write32(BIT(channel), (mem_addr_t)&cfg->reg->CHNL_PRI_ALT_SET);
	sys_write32(BIT(channel), (mem_addr_t)&cfg->reg->CHNL_REQ_MASK_CLR);

	RSI_UDMA_SetChannelScatterGatherTransfer(udma_handle, channel, config->block_count,
						 sg_desc_base_addr, transfer_type);
	return 0;
}

static int siwx917_channel_config(const struct device *dev, RSI_UDMA_HANDLE_T udma_handle,
				  uint32_t channel, const struct dma_config *config)
{
	uint32_t dma_transfer_num = config->head_block->block_size / config->source_data_size;
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	UDMA_RESOURCES udma_resources = {
		.reg = cfg->reg,
		.udma_irq_num = cfg->irq_number,
		/* SRAM address where UDMA descriptor is stored */
		.desc = cfg->sram_desc_addr,
	};
	RSI_UDMA_CHA_CONFIG_DATA_T channel_control = {
		.transferType = UDMA_MODE_BASIC,
	};
	RSI_UDMA_CHA_CFG_T channel_config = {};
	int status;

	if (siwx917_transfer_direction(config->channel_direction) < 0) {
		return -EINVAL;
	}

	channel_config.channelPrioHigh = config->channel_priority;
	channel_config.periphReq = siwx917_transfer_direction(config->channel_direction);
	channel_config.dmaCh = channel;

	if (channel_config.periphReq) {
		/* Arbitration power for peripheral<->memory transfers */
		channel_control.rPower = ARBSIZE_1;
	} else {
		/* Arbitration power for mem-mem transfers */
		channel_control.rPower = ARBSIZE_1024;
	}

	/* Obtain the number of transfers */
	if (dma_transfer_num >= DMA_MAX_TRANSFER_COUNT) {
		/* Maximum number of transfers is 1024 */
		channel_control.totalNumOfDMATrans = DMA_MAX_TRANSFER_COUNT - 1;
	} else {
		channel_control.totalNumOfDMATrans = dma_transfer_num;
	}

	if (siwx917_data_width(config->source_data_size) < 0 ||
	    siwx917_data_width(config->dest_data_size) < 0) {
		return -EINVAL;
	}

	if (siwx917_is_burst_length_valid(config->source_burst_length) == false ||
	    siwx917_is_burst_length_valid(config->dest_burst_length) == false) {
		return -EINVAL;
	}

	channel_control.srcSize = siwx917_data_width(config->source_data_size);
	channel_control.dstSize = siwx917_data_width(config->dest_data_size);
	if (siwx917_addr_adjustment(config->head_block->source_addr_adj) < 0 ||
	    siwx917_addr_adjustment(config->head_block->dest_addr_adj) < 0) {
		return -EINVAL;
	}

	if (siwx917_addr_adjustment(config->head_block->source_addr_adj) == 0) {
		channel_control.srcInc = channel_control.srcSize;
	} else {
		channel_control.srcInc = UDMA_SRC_INC_NONE;
	}

	if (siwx917_addr_adjustment(config->head_block->dest_addr_adj) == 0) {
		channel_control.dstInc = channel_control.dstSize;
	} else {
		channel_control.dstInc = UDMA_DST_INC_NONE;
	}

	status = UDMAx_ChannelConfigure(&udma_resources, (uint8_t)channel,
					config->head_block->source_address,
					config->head_block->dest_address,
					dma_transfer_num, channel_control,
					&channel_config, NULL, data->chan_info, udma_handle);
	if (status) {
		return -EIO;
	}

	return 0;
}

/* Function to configure UDMA channel for transfer */
static int siwx917_dma_configure(const struct device *dev, uint32_t channel,
				 struct dma_config *config)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->udma_handle;
	int status;

	/* Expecting a fixed channel number between 0-31 for dma0 and 0-11 for ulpdma */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}

	/* Disable the channel before configuring */
	if (RSI_UDMA_ChannelDisable(udma_handle, channel) != 0) {
		return -EIO;
	}

	if (config->channel_priority != DMA_CH_PRIORITY_LOW &&
	    config->channel_priority != DMA_CH_PRIORITY_HIGH) {
		return -EINVAL;
	}

	if (config->cyclic) {
		/* Cyclic DMA feature is not supported by siwx917 HW */
		return -EINVAL;
	}

	/* Configure dma channel for transfer */
	if (config->head_block->source_gather_en || config->head_block->dest_scatter_en) {
		/* Configure DMA for a Scatter-Gather transfer */
		status = siwx917_sg_config(dev, udma_handle, channel, config);
	} else {
		/* Configure dma channel for transfer */
		status = siwx917_channel_config(dev, udma_handle, channel, config);
	}

	if (status) {
		return status;
	}

	data->dma_callback = config->dma_callback;
	data->cb_data = config->user_data;
	return 0;
}

/* Function to reload UDMA channel for new transfer */
static int siwx917_dma_reload(const struct device *dev, uint32_t channel, uint32_t src,
			      uint32_t dst, size_t size)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->udma_handle;
	uint32_t desc_src_addr;
	uint32_t desc_dst_addr;
	uint32_t length;
	RSI_UDMA_DESC_T *udma_table = cfg->sram_desc_addr;

	/* Expecting a fixed channel number between 0-31 for dma0 and 0-11 for ulpdma */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}

	/* Disable the channel before reloading transfer */
	if (RSI_UDMA_ChannelDisable(udma_handle, channel) != 0) {
		return -EIO;
	}

	/* Update new channel info to dev->data structure */
	data->chan_info[channel].SrcAddr = src;
	data->chan_info[channel].DestAddr = dst;
	data->chan_info[channel].Size = size;

	/* Update new transfer size to dev->data structure */
	if (size >= DMA_MAX_TRANSFER_COUNT) {
		data->chan_info[channel].Cnt = DMA_MAX_TRANSFER_COUNT - 1;
	} else {
		data->chan_info[channel].Cnt = size;
	}

	/* Program the DMA descriptors with new transfer data information. */
	if (udma_table[channel].vsUDMAChaConfigData1.srcInc != UDMA_SRC_INC_NONE) {
		length = data->chan_info[channel].Cnt
			 << udma_table[channel].vsUDMAChaConfigData1.srcInc;
		desc_src_addr = src + (length - 1);
		udma_table[channel].pSrcEndAddr = (void *)desc_src_addr;
	}

	if (udma_table[channel].vsUDMAChaConfigData1.dstInc != UDMA_SRC_INC_NONE) {
		length = data->chan_info[channel].Cnt
			 << udma_table[channel].vsUDMAChaConfigData1.dstInc;
		desc_dst_addr = dst + (length - 1);
		udma_table[channel].pDstEndAddr = (void *)desc_dst_addr;
	}

	udma_table[channel].vsUDMAChaConfigData1.totalNumOfDMATrans = data->chan_info[channel].Cnt;
	udma_table[channel].vsUDMAChaConfigData1.transferType = UDMA_MODE_BASIC;

	return 0;
}

/* Function to start a DMA transfer */
static int siwx917_dma_start(const struct device *dev, uint32_t channel)
{
	const struct dma_siwx917_config *cfg = dev->config;
	RSI_UDMA_DESC_T *udma_table = cfg->sram_desc_addr;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->udma_handle;

	/* Expecting a fixed channel number between 0-31 for dma0 and 0-11 for ulpdma */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}

	if (RSI_UDMA_ChannelEnable(udma_handle, channel) != 0) {
		return -EINVAL;
	}

	/* Check if the transfer type is memory-memory */
	if (udma_table[channel].vsUDMAChaConfigData1.srcInc != UDMA_SRC_INC_NONE &&
	    udma_table[channel].vsUDMAChaConfigData1.dstInc != UDMA_DST_INC_NONE) {
		/* Apply software trigger to start transfer */
		sys_set_bit((mem_addr_t)&cfg->reg->CHNL_SW_REQUEST, channel);
	}

	return 0;
}

/* Function to stop a DMA transfer */
static int siwx917_dma_stop(const struct device *dev, uint32_t channel)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->udma_handle;

	/* Expecting a fixed channel number between 0-31 for dma0 and 0-11 for ulpdma */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}

	if (RSI_UDMA_ChannelDisable(udma_handle, channel) != 0) {
		return -EIO;
	}

	return 0;
}

/* Function to fetch DMA channel status */
static int siwx917_dma_get_status(const struct device *dev, uint32_t channel,
				  struct dma_status *stat)
{
	const struct dma_siwx917_config *cfg = dev->config;
	RSI_UDMA_DESC_T *udma_table = cfg->sram_desc_addr;

	/* Expecting a fixed channel number between 0-31 for dma0 and 0-11 for ulpdma */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}

	/* Read the channel status register */
	stat->busy = sys_test_bit((mem_addr_t)&cfg->reg->CHANNEL_STATUS_REG, channel);

	/* Obtain the transfer direction from channel descriptors */
	if (udma_table[channel].vsUDMAChaConfigData1.srcInc == UDMA_SRC_INC_NONE) {
		stat->dir = PERIPHERAL_TO_MEMORY;
	} else if (udma_table[channel].vsUDMAChaConfigData1.dstInc == UDMA_DST_INC_NONE) {
		stat->dir = MEMORY_TO_PERIPHERAL;
	} else {
		stat->dir = MEMORY_TO_MEMORY;
	}

	return 0;
}

/* Function to initialize DMA peripheral */
static int siwx917_dma_init(const struct device *dev)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = NULL;
	UDMA_RESOURCES udma_resources = {
		.reg = cfg->reg, /* UDMA register base address */
		.udma_irq_num = cfg->irq_number,
		.desc = cfg->sram_desc_addr,
	};
	int ret;

	ret = clock_control_on(cfg->clock_dev, cfg->clock_subsys);
	if (ret) {
		return ret;
	}

	udma_handle = UDMAx_Initialize(&udma_resources, udma_resources.desc, NULL,
				       (uint32_t *)&data->udma_handle);
	if (udma_handle != &data->udma_handle) {
		return -EINVAL;
	}

	/* Connect the DMA interrupt */
	cfg->irq_configure();

	if (UDMAx_DMAEnable(&udma_resources, udma_handle) != 0) {
		return -EBUSY;
	}

	return 0;
}

static void siwx917_dma_isr(const struct device *dev)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	UDMA_RESOURCES udma_resources = {
		.reg = cfg->reg,
		.udma_irq_num = cfg->irq_number,
		.desc = cfg->sram_desc_addr,
	};
	uint8_t channel;

	/* Disable the IRQ to prevent the ISR from being triggered by
	 * interrupts from other DMA channels.
	 */
	irq_disable(cfg->irq_number);
	channel = find_lsb_set(cfg->reg->UDMA_DONE_STATUS_REG);
	/* Identify the interrupt channel */
	if (!channel || channel > cfg->channels) {
		goto out;
	}

	/* find_lsb_set() returns 1 indexed value */
	channel -= 1;

	if (data->sg_desc_addr_info[channel]) {
		/* A Scatter-Gather transfer is completed, free the allocated descriptors */
		if (sys_mem_blocks_free_contiguous(data->dma_desc_pool,
						   (void *)data->sg_desc_addr_info[channel],
						   data->chan_info[channel].Cnt)) {
			sys_write32(BIT(channel), (mem_addr_t)&cfg->reg->UDMA_DONE_STATUS_REG);
			goto out;
		}

		data->chan_info[channel].Cnt = 0;
		data->chan_info[channel].Size = 0;
		data->sg_desc_addr_info[channel] = 0;
	}

	if (data->chan_info[channel].Cnt == data->chan_info[channel].Size) {
		if (data->dma_callback) {
			/* Transfer complete, call user callback */
			data->dma_callback(dev, data->cb_data, channel, 0);
		}

		sys_write32(BIT(channel), (mem_addr_t)&cfg->reg->UDMA_DONE_STATUS_REG);
	} else {
		/* Call UDMA ROM IRQ handler. */
		ROMAPI_UDMA_WRAPPER_API->uDMAx_IRQHandler(&udma_resources, udma_resources.desc,
							  data->chan_info);
		/* Is a Memory-to-memory Transfer */
		if (udma_resources.desc[channel].vsUDMAChaConfigData1.srcInc != UDMA_SRC_INC_NONE &&
		    udma_resources.desc[channel].vsUDMAChaConfigData1.dstInc != UDMA_DST_INC_NONE) {
			/* Set the software trigger bit for starting next transfer */
			sys_set_bit((mem_addr_t)&cfg->reg->CHNL_SW_REQUEST, channel);
		}
	}

out:
	/* Enable the IRQ to restore interrupt functionality for other DMA channels */
	irq_enable(cfg->irq_number);
}

/* Store the Si91x DMA APIs */
static const struct dma_driver_api siwx917_dma_driver_api = {
	.config = siwx917_dma_configure,
	.reload = siwx917_dma_reload,
	.start = siwx917_dma_start,
	.stop = siwx917_dma_stop,
	.get_status = siwx917_dma_get_status,
};

#define SIWX917_DMA_INIT(inst)                                                                     \
	static UDMA_Channel_Info dma_channel_info_##inst[DT_INST_PROP(inst, dma_channels)];        \
	static uint32_t dma_sg_desc_addr_info_##inst[DT_INST_PROP(inst, dma_channels)];            \
	SYS_MEM_BLOCKS_DEFINE_STATIC(desc_pool_##inst, sizeof(RSI_UDMA_DESC_T),                    \
				     CONFIG_DMA_SILABS_SIWX917_SG_BUFFER_COUNT, 4);                \
	static struct dma_siwx917_data dma_data_##inst = {                                         \
		.chan_info = dma_channel_info_##inst,                                              \
		.sg_desc_addr_info = dma_sg_desc_addr_info_##inst,                                 \
		.dma_desc_pool = &desc_pool_##inst,                                                \
	};                                                                                         \
	static void siwx917_dma_irq_configure_##inst(void)                                         \
	{                                                                                          \
		IRQ_CONNECT(DT_INST_IRQ(inst, irq), DT_INST_IRQ(inst, priority), siwx917_dma_isr,  \
			    DEVICE_DT_INST_GET(inst), 0);                                          \
		irq_enable(DT_INST_IRQ(inst, irq));                                                \
	}                                                                                          \
	static const struct dma_siwx917_config dma_cfg_##inst = {                                  \
		.clock_dev = DEVICE_DT_GET(DT_INST_CLOCKS_CTLR(inst)),                             \
		.clock_subsys = (clock_control_subsys_t)DT_INST_PHA(inst, clocks, clkid),          \
		.reg = (UDMA0_Type *)DT_INST_REG_ADDR(inst),                                       \
		.channels = DT_INST_PROP(inst, dma_channels),                                      \
		.irq_number = DT_INST_PROP_BY_IDX(inst, interrupts, 0),                            \
		.sram_desc_addr = (RSI_UDMA_DESC_T *)DT_INST_PROP(inst, silabs_sram_desc_addr),    \
		.irq_configure = siwx917_dma_irq_configure_##inst,                                 \
	};                                                                                         \
	DEVICE_DT_INST_DEFINE(inst, &siwx917_dma_init, NULL, &dma_data_##inst, &dma_cfg_##inst,    \
			      PRE_KERNEL_1, CONFIG_DMA_INIT_PRIORITY, &siwx917_dma_driver_api);

DT_INST_FOREACH_STATUS_OKAY(SIWX917_DMA_INIT)
