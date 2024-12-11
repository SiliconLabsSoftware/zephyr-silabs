/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/irq.h>
#include <zephyr/sys/util.h>
#include <zephyr/device.h>
#include <zephyr/drivers/dma.h>
#include <zephyr/logging/log.h>
#include <zephyr/types.h>
#include "rsi_rom_udma_wrapper.h"
#include "rsi_rom_udma.h"
#include "rsi_udma.h"
#include "sl_status.h"

#define DT_DRV_COMPAT                    silabs_siwx917_dma
#define DMA_MAX_TRANSFER_COUNT           1024
#define DMA_CH_PRIORITY_HIGH             1
#define DMA_CH_PRIORITY_LOW              0
#define VALID_BURST_LENGTH               0
#define UDMA_ADDR_INC_NONE               0X03
#define UDMA_MODE_PER_ALT_SCATTER_GATHER 0x07

LOG_MODULE_REGISTER(si91x_dma, CONFIG_DMA_LOG_LEVEL);

struct dma_sg_descriptor_allocator {
	RSI_UDMA_DESC_T sg_transfer_desc_table[CONFIG_SG_BUFFER_COUNT]; /* DMA descriptors in
									   contiguous memory */
	uint8_t free_desc[CONFIG_SG_BUFFER_COUNT]; /* Allocation status of descriptors */
};

struct dma_siwx917_config {
	UDMA0_Type *reg;                 /* UDMA register base address */
	uint8_t channels;                /* UDMA channel count */
	uint8_t irq_number;              /* IRQ number */
	RSI_UDMA_DESC_T *sram_desc_addr; /* SRAM Address for UDMA Descriptor Storage */
	void (*irq_configure)(void);     /* IRQ configure function */
};

struct dma_siwx917_data {
	UDMA_Channel_Info *chan_info;
	dma_callback_t dma_callback; /* User callback */
	void *cb_data;               /* User callback data */
	struct dma_sg_descriptor_allocator
		*sg_transfer_desc_block;     /* Pointer to scatter-gather descriptors block */
	RSI_UDMA_DATACONTEXT_T dma_rom_buff; /* Buffer to store UDMA handle */
					     /* related information */
};

static inline int siwx917_dma_is_peripheral_request(uint32_t dir)
{
	if (dir == MEMORY_TO_MEMORY) {
		return 0;
	}
	if (dir == MEMORY_TO_PERIPHERAL || dir == PERIPHERAL_TO_MEMORY) {
		return 1;
	}
	return -1;
}

static inline int siwx917_dma_data_width(uint32_t data_width)
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

static inline int siwx917_dma_burst_length(uint32_t blen)
{
	switch (blen / 8) {
	case 1:
		return VALID_BURST_LENGTH; /* 8-bit burst */
	default:
		return -EINVAL;
	}
}

static inline int siwx917_dma_addr_adjustment(uint32_t adjustment)
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

/* Releases a range of scatter-gather descriptors */
static inline void
release_sg_desc_blocks(struct dma_sg_descriptor_allocator *sg_transfer_desc_block,
		       uint32_t start_index, uint32_t count)
{
	/* Loop through the range of descriptors to be released */
	for (int index = start_index; index < (start_index + count); index++) {
		/* Mark each descriptor as free */
		sg_transfer_desc_block->free_desc[index] = 0;
	}
}

/* Requests a base address of contiguous memory for scatter-gather descriptor table */
static int request_sg_desc_base_addr(struct dma_sg_descriptor_allocator *sg_transfer_desc_block,
				     RSI_UDMA_DESC_T **desc_base_addr, uint32_t block_count)
{
	uint32_t contiguous_blocks = 0;
	uint32_t index1;

	/* Find contiguous free blocks */
	for (index1 = 0; index1 < CONFIG_SG_BUFFER_COUNT; index1++) {
		if (sg_transfer_desc_block->free_desc[index1] != 0) {
			contiguous_blocks = 0;
			continue;
		}
		contiguous_blocks++;
		/* Check if the required number of contiguous blocks is found */
		if (contiguous_blocks == block_count) {
			*desc_base_addr =
				&sg_transfer_desc_block
					 ->sg_transfer_desc_table[index1 - block_count + 1];
			goto out;
		}
	}
	/* Return an error if not enough contiguous blocks are found */
	return -EIO;
out:
	for (int index2 = (index1 - block_count + 1); index2 < index1; index2++) {
		sg_transfer_desc_block->free_desc[index2] = 1;
	}
	/* Return the starting index of the allocated blocks */
	return (index1 - block_count + 1);
}

/* Sets up the scatter-gather descriptor table for a DMA transfer */
static int set_scatter_gather_desc(RSI_UDMA_DESC_T *sg_desc_base_addr, struct dma_config *config,
				   uint8_t *transfer_type)
{
	int peripheral_request = siwx917_dma_is_peripheral_request(config->channel_direction);
	struct dma_block_config *block_addr = config->head_block;

	if (peripheral_request < 0) {
		return -EINVAL;
	} else if (peripheral_request) {
		*transfer_type = UDMA_MODE_PER_SCATTER_GATHER;
	}
	for (int index = 0; index < config->block_count; index++) {
		/* Set the source and destination end addresses */
		sg_desc_base_addr[index].pSrcEndAddr =
			(uint32_t *)(block_addr->source_address +
				     (block_addr->block_size - config->source_data_size));
		sg_desc_base_addr[index].pDstEndAddr =
			(uint32_t *)(block_addr->dest_address +
				     (block_addr->block_size - config->dest_data_size));
		/* Set the source and destination data sizes */
		sg_desc_base_addr[index].vsUDMAChaConfigData1.srcSize =
			siwx917_dma_data_width(config->source_data_size);
		sg_desc_base_addr[index].vsUDMAChaConfigData1.dstSize =
			siwx917_dma_data_width(config->dest_data_size);
		/* Calculate the number of DMA transfers required */
		block_addr->block_size /= config->source_data_size;
		if (block_addr->block_size > DMA_MAX_TRANSFER_COUNT) {
			return -EINVAL;
		}
		/* Set the total number of DMA transfers */
		sg_desc_base_addr[index].vsUDMAChaConfigData1.totalNumOfDMATrans =
			block_addr->block_size - 1;
		/* Set the transfer type based on whether it is a peripheral request */
		sg_desc_base_addr[index].vsUDMAChaConfigData1.transferType =
			peripheral_request ? UDMA_MODE_PER_ALT_SCATTER_GATHER
					   : UDMA_MODE_MEM_ALT_SCATTER_GATHER;
		/* Set the arbitration size */
		sg_desc_base_addr[index].vsUDMAChaConfigData1.rPower = ARBSIZE_1;
		if (siwx917_dma_addr_adjustment(block_addr->source_addr_adj) < 0 ||
		    siwx917_dma_addr_adjustment(block_addr->dest_addr_adj) < 0) {
			return -EINVAL;
		}
		/* Set source and destination address increments */
		sg_desc_base_addr[index].vsUDMAChaConfigData1.srcInc =
			siwx917_dma_addr_adjustment(block_addr->source_addr_adj)
				? UDMA_SRC_INC_NONE
				: siwx917_dma_data_width(config->source_data_size);
		sg_desc_base_addr[index].vsUDMAChaConfigData1.dstInc =
			siwx917_dma_addr_adjustment(block_addr->dest_addr_adj)
				? UDMA_DST_INC_NONE
				: siwx917_dma_data_width(config->dest_data_size);
		/* Move to the next block */
		block_addr = block_addr->next_block;
	}
	/* Set the transfer type for the last descriptor */
	sg_desc_base_addr[config->block_count - 1].vsUDMAChaConfigData1.transferType =
		peripheral_request ? UDMA_MODE_BASIC : UDMA_MODE_AUTO;
	return 0;
}

/* Configure DMA for scatter-gather transfer */
static int dma_scatter_gather_config(const struct device *dev, RSI_UDMA_HANDLE_T udma_handle,
				     uint32_t channel, struct dma_config *config)
{
	uint8_t transfer_type = UDMA_MODE_MEM_SCATTER_GATHER;
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	RSI_UDMA_DESC_T *sg_desc_base_addr = NULL;
	int block_alloc_start_index;

	if (siwx917_dma_data_width(config->source_data_size) < 0 ||
	    siwx917_dma_data_width(config->dest_data_size) < 0) {
		return -EINVAL;
	}
	if (config->block_count > CONFIG_SG_BUFFER_COUNT) {
		return -EINVAL;
	}
	/* Request base address for scatter-gather descriptor table */
	block_alloc_start_index = request_sg_desc_base_addr(
		data->sg_transfer_desc_block, &sg_desc_base_addr, config->block_count);
	if (block_alloc_start_index < 0) {
		return -EIO;
	}
	if (set_scatter_gather_desc(sg_desc_base_addr, config, &transfer_type)) {
		return -EINVAL;
	}
	/* This channel information is used to distinguish scatter-gather transfers and */
	/* free the allocated descriptors in sg_transfer_desc_block */
	data->chan_info[channel].SrcAddr = 0;
	data->chan_info[channel].DestAddr = 0;
	data->chan_info[channel].Cnt = config->block_count;
	data->chan_info[channel].Size = block_alloc_start_index;
	RSI_UDMA_InterruptClear(udma_handle, channel);
	RSI_UDMA_ErrorStatusClear(udma_handle);
	if (cfg->reg == UDMA0) {
		M4SS_UDMA_INTR_SEL |= BIT(channel);
	} else {
		cfg->reg->UDMA_INTR_MASK_REG |= BIT(channel);
	}
	cfg->reg->CHNL_PRI_ALT_SET = BIT(channel);
	cfg->reg->CHNL_REQ_MASK_CLR = BIT(channel);
	RSI_UDMA_SetChannelScatterGatherTransfer(udma_handle, channel, config->block_count,
						 sg_desc_base_addr, transfer_type);
	return 0;
}

static int dma_channel_config(const struct device *dev, RSI_UDMA_HANDLE_T udma_handle,
			      uint32_t channel, struct dma_config *config,
			      UDMA_Channel_Info *channel_info)
{
	const struct dma_siwx917_config *cfg = dev->config;
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

	channel_config.channelPrioHigh = config->channel_priority;
	if (siwx917_dma_is_peripheral_request(config->channel_direction) < 0) {
		return -EINVAL;
	}
	channel_config.periphReq = siwx917_dma_is_peripheral_request(config->channel_direction);
	channel_config.dmaCh = channel;
	if (channel_config.periphReq) {
		/* Arbitration power for peripheral<->memory transfers */
		channel_control.rPower = ARBSIZE_1;
	} else {
		/* Arbitration power for mem-mem transfers */
		channel_control.rPower = ARBSIZE_1024;
	}
	/* Obtain the number of transfers */
	config->head_block->block_size /= config->source_data_size;
	if (config->head_block->block_size >= DMA_MAX_TRANSFER_COUNT) {
		/* Maximum number of transfers is 1024 */
		channel_control.totalNumOfDMATrans = DMA_MAX_TRANSFER_COUNT - 1;
	} else {
		channel_control.totalNumOfDMATrans = config->head_block->block_size;
	}
	if (siwx917_dma_data_width(config->source_data_size) < 0 ||
	    siwx917_dma_data_width(config->dest_data_size) < 0) {
		return -EINVAL;
	}
	if (siwx917_dma_burst_length(config->source_burst_length) < 0 ||
	    siwx917_dma_burst_length(config->dest_burst_length) < 0) {
		return -EINVAL;
	}
	channel_control.srcSize = siwx917_dma_data_width(config->source_data_size);
	channel_control.dstSize = siwx917_dma_data_width(config->dest_data_size);
	if (siwx917_dma_addr_adjustment(config->head_block->source_addr_adj) < 0 ||
	    siwx917_dma_addr_adjustment(config->head_block->dest_addr_adj) < 0) {
		return -EINVAL;
	}
	if (siwx917_dma_addr_adjustment(config->head_block->source_addr_adj) == 0) {
		channel_control.srcInc = channel_control.srcSize;
	} else {
		channel_control.srcInc = UDMA_SRC_INC_NONE;
	}
	if (siwx917_dma_addr_adjustment(config->head_block->dest_addr_adj) == 0) {
		channel_control.dstInc = channel_control.dstSize;
	} else {
		channel_control.dstInc = UDMA_DST_INC_NONE;
	}
	status = UDMAx_ChannelConfigure(
		&udma_resources, (uint8_t)channel, config->head_block->source_address,
		config->head_block->dest_address, config->head_block->block_size, channel_control,
		&channel_config, NULL, channel_info, udma_handle);
	if (status) {
		return -EIO;
	}
	return 0;
}

/* Function to configure UDMA channel for transfer */
static int dma_siwx917_configure(const struct device *dev, uint32_t channel,
				 struct dma_config *config)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->dma_rom_buff;
	int status;

	/* Expecting a fixed channel number between 0-31 for udma0 and 0-11 for udma1 */
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

	if (config->head_block->source_gather_en || config->head_block->dest_scatter_en) {
		/* Configure DMA for a Scatter-Gather transfer */
		status = dma_scatter_gather_config(dev, udma_handle, channel, config);
	} else {
		/* Configure dma channel for transfer */
		status = dma_channel_config(dev, udma_handle, channel, config, data->chan_info);
	}
	data->dma_callback = config->dma_callback;
	data->cb_data = config->user_data;
	if (status) {
		return status;
	}
	return 0;
}

/* Function to reload UDMA channel for new transfer */
static int dma_siwx917_reload(const struct device *dev, uint32_t channel, uint32_t src,
			      uint32_t dst, size_t size)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->dma_rom_buff;
	uint32_t desc_src_addr;
	uint32_t desc_dst_addr;
	uint32_t length;
	RSI_UDMA_DESC_T *udma_table = cfg->sram_desc_addr;

	/* Expecting a fixed channel number between 0-31 for udma0 and 0-11 for udma1 */
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
static int dma_siwx917_start(const struct device *dev, uint32_t channel)
{
	const struct dma_siwx917_config *cfg = dev->config;
	RSI_UDMA_DESC_T *udma_table = cfg->sram_desc_addr;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->dma_rom_buff;

	/* Expecting a fixed channel number between 0-31 for udma0 and 0-11 for udma1 */
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
		cfg->reg->CHNL_SW_REQUEST |= BIT(channel);
	}
	return 0;
}

/* Function to stop a DMA transfer */
static int dma_siwx917_stop(const struct device *dev, uint32_t channel)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = &data->dma_rom_buff;

	/* Expecting a fixed channel number between 0-31 for udma0 and 0-11 for udma1 */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}
	if (RSI_UDMA_ChannelDisable(udma_handle, channel) != 0) {
		return -EIO;
	}
	return 0;
}

/* Function to fetch DMA channel status */
static int dma_siwx917_get_status(const struct device *dev, uint32_t channel,
				  struct dma_status *stat)
{
	const struct dma_siwx917_config *cfg = dev->config;
	RSI_UDMA_DESC_T *udma_table = cfg->sram_desc_addr;

	/* Expecting a fixed channel number between 0-31 for udma0 and 0-11 for udma1 */
	if (channel >= cfg->channels) {
		return -EINVAL;
	}
	/* Read the channel status register */
	if (cfg->reg->CHANNEL_STATUS_REG & BIT(channel)) {
		stat->busy = 1;
	} else {
		stat->busy = 0;
	}

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
static int dma_siwx917_init(const struct device *dev)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	void *udma_handle = NULL;
	UDMA_RESOURCES udma_resources = {
		.reg = cfg->reg, /* UDMA register base address */
		.udma_irq_num = cfg->irq_number,
		.desc = cfg->sram_desc_addr,
	};

	udma_handle = UDMAx_Initialize(&udma_resources, udma_resources.desc, NULL,
				       (uint32_t *)&data->dma_rom_buff);
	if (udma_handle != &data->dma_rom_buff) {
		return -EINVAL;
	}

	/* Connect the DMA interrupt */
	cfg->irq_configure();

	if (UDMAx_DMAEnable(&udma_resources, udma_handle) != 0) {
		return -EBUSY;
	}
	return 0;
}

static void dma_siwx917_isr(const struct device *dev)
{
	const struct dma_siwx917_config *cfg = dev->config;
	struct dma_siwx917_data *data = dev->data;
	UDMA_RESOURCES udma_resources = {
		.reg = cfg->reg,
		.udma_irq_num = cfg->irq_number,
		.desc = cfg->sram_desc_addr,
	};
	uint8_t channel;

	/* Disable the IRQ to prevent the ISR from being triggered by */
	/* interrupts from other DMA channels */
	irq_disable(cfg->irq_number);
	channel = find_lsb_set(cfg->reg->UDMA_DONE_STATUS_REG);
	/* Identify the interrupt channel */
	if (!channel || channel > cfg->channels) {
		goto out;
	}
	/* find_lsb_set() returns 1 indexed value */
	channel -= 1;
	if (data->chan_info[channel].SrcAddr == 0 && data->chan_info[channel].DestAddr == 0) {
		/* A Scatter-Gather transfer is completed, free the allocated descriptors */
		release_sg_desc_blocks(data->sg_transfer_desc_block, data->chan_info[channel].Size,
				       data->chan_info[channel].Cnt);
		goto out;
	}
	if (data->chan_info[channel].Cnt == data->chan_info[channel].Size) {
		goto out;
	} else {
		/* Call UDMA ROM IRQ handler. */
		ROMAPI_UDMA_WRAPPER_API->uDMAx_IRQHandler(&udma_resources, udma_resources.desc,
							  data->chan_info);
		/* Is a Memory-to-memory Transfer */
		if (udma_resources.desc[channel].vsUDMAChaConfigData1.srcInc != UDMA_SRC_INC_NONE &&
		    udma_resources.desc[channel].vsUDMAChaConfigData1.dstInc != UDMA_DST_INC_NONE) {
			/* Set the software trigger bit for starting next transfer */
			cfg->reg->CHNL_SW_REQUEST |= BIT(channel);
		}
	}
out:
	if (data->dma_callback) {
		/* Transfer complete, call user callback */
		data->dma_callback(dev, data->cb_data, channel, 0);
	}
	cfg->reg->UDMA_DONE_STATUS_REG = BIT(channel);
	/* Enable the IRQ to restore interrupt functionality for other DMA channels */
	irq_enable(cfg->irq_number);
}

/* Store the Si91x DMA APIs */
static const struct dma_driver_api siwx917_dma_driver_api = {
	.config = dma_siwx917_configure,
	.reload = dma_siwx917_reload,
	.start = dma_siwx917_start,
	.stop = dma_siwx917_stop,
	.get_status = dma_siwx917_get_status,
};

#define SIWX917_DMA_INIT(inst)                                                                     \
	static UDMA_Channel_Info dma##inst##_channel_info[DT_INST_PROP(inst, dma_channels)];       \
	static struct dma_sg_descriptor_allocator dma##inst##_desc_allocator;                      \
	static struct dma_siwx917_data dma##inst##_data = {                                        \
		.chan_info = dma##inst##_channel_info,                                             \
		.sg_transfer_desc_block = &dma##inst##_desc_allocator,                             \
	};                                                                                         \
	static void siwx917_dma##inst##_irq_configure(void)                                        \
	{                                                                                          \
		IRQ_CONNECT(DT_INST_IRQ(inst, irq), DT_INST_IRQ(inst, priority), dma_siwx917_isr,  \
			    DEVICE_DT_INST_GET(inst), 0);                                          \
		irq_enable(DT_INST_IRQ(inst, irq));                                                \
	}                                                                                          \
	static const struct dma_siwx917_config dma##inst##_cfg = {                                 \
		.reg = (UDMA0_Type *)DT_INST_REG_ADDR(inst),                                       \
		.channels = DT_INST_PROP(inst, dma_channels),                                      \
		.irq_number = DT_INST_PROP_BY_IDX(inst, interrupts, 0),                            \
		.sram_desc_addr = (RSI_UDMA_DESC_T *)DT_INST_PROP(inst, silabs_sram_desc_addr),    \
		.irq_configure = siwx917_dma##inst##_irq_configure,                                \
	};                                                                                         \
	DEVICE_DT_INST_DEFINE(inst, &dma_siwx917_init, NULL, &dma##inst##_data, &dma##inst##_cfg,  \
			      PRE_KERNEL_1, CONFIG_DMA_INIT_PRIORITY, &siwx917_dma_driver_api);

DT_INST_FOREACH_STATUS_OKAY(SIWX917_DMA_INIT)
