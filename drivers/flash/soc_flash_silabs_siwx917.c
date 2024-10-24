/*
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#define DT_DRV_COMPAT silabs_siwx917_flash_controller

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>

#include "sl_si91x_driver.h"

LOG_MODULE_REGISTER(siwx917_soc_flash);

struct siwx917_config {
	uintptr_t base_address;
	uint32_t size;
	uint32_t write_block_size;
	uint32_t erase_block_size;
	struct flash_parameters flash_parameters;
#ifdef CONFIG_FLASH_PAGE_LAYOUT
	struct flash_pages_layout flash_pages_layout;
#endif
};

struct siwx917_data {
	struct k_sem lock;
};

static bool flash_siwx917_range_is_in_bounds(const struct device *dev, off_t offset, size_t len)
{
	const struct siwx917_config *cfg = dev->config;

	/* Note: If offset < __rom_region_end, the user to overwriting the current firmware. User
	 * is probably doing a mistake, but not an error from this driver point of view.
	 */
	if (offset < 0) {
		return false;
	}
	if (offset + len > cfg->size) {
		return false;
	}
	return true;
}

static const struct flash_parameters *flash_siwx917_get_parameters(const struct device *dev)
{
	const struct siwx917_config *cfg = dev->config;

	return &cfg->flash_parameters;
}

static int flash_siwx917_read(const struct device *dev, off_t offset, void *buf, size_t len)
{
	const struct siwx917_config *cfg = dev->config;
	struct siwx917_data *data = dev->data;
	void *location = (void *)(cfg->base_address + offset);

	if (!flash_siwx917_range_is_in_bounds(dev, offset, len)) {
		return -EINVAL;
	}
	k_sem_take(&data->lock, K_FOREVER);
	memcpy(buf, location, len);
	k_sem_give(&data->lock);
	return 0;
}

static int flash_siwx917_write(const struct device *dev, off_t offset, const void *buf, size_t len)
{
	const struct siwx917_config *cfg = dev->config;
	struct siwx917_data *data = dev->data;
	uint32_t ret;

	if (!flash_siwx917_range_is_in_bounds(dev, offset, len)) {
		return -EINVAL;
	}
	if (offset % cfg->write_block_size) {
		return -EINVAL;
	}
	if (len % cfg->write_block_size) {
		return -EINVAL;
	}
	k_sem_take(&data->lock, K_FOREVER);
	ret = sl_si91x_command_to_write_common_flash(cfg->base_address + offset, (void *)buf, len,
						     false);
	k_sem_give(&data->lock);
	if (ret) {
		return -EIO;
	}
	return 0;
}

static int flash_siwx917_erase(const struct device *dev, off_t offset, size_t len)
{
	const struct siwx917_config *cfg = dev->config;
	struct siwx917_data *data = dev->data;
	uint32_t ret;

	if (!flash_siwx917_range_is_in_bounds(dev, offset, len)) {
		return -EINVAL;
	}
	if (offset % cfg->erase_block_size) {
		return -EINVAL;
	}
	if (len % cfg->erase_block_size) {
		return -EINVAL;
	}
	k_sem_take(&data->lock, K_FOREVER);
	ret = sl_si91x_command_to_write_common_flash(cfg->base_address + offset, NULL, len, true);
	k_sem_give(&data->lock);
	if (ret) {
		return -EIO;
	}
	return 0;
}

#ifdef CONFIG_FLASH_PAGE_LAYOUT
static void flash_siwx917_page_layout(const struct device *dev,
				      const struct flash_pages_layout **layout, size_t *layout_size)
{
	const struct siwx917_config *cfg = dev->config;

	*layout = &cfg->flash_pages_layout;
	*layout_size = 1;
}
#endif

static const struct flash_driver_api siwx917_api = {
	.read = flash_siwx917_read,
	.write = flash_siwx917_write,
	.erase = flash_siwx917_erase,
	.get_parameters = flash_siwx917_get_parameters,
#ifdef CONFIG_FLASH_PAGE_LAYOUT
	.page_layout = flash_siwx917_page_layout,
#endif
};

static int flash_siwx917_init(const struct device *dev)
{
	struct siwx917_data *data = dev->data;

	k_sem_init(&data->lock, 1, 1);
	return 0;
}

#ifdef CONFIG_FLASH_PAGE_LAYOUT
#define SIWX917_PAGE_LAYOUT_FLASH_INIT(n)                                                          \
	.flash_pages_layout.pages_count = DT_REG_SIZE(n) / DT_PROP(n, erase_block_size),           \
	.flash_pages_layout.pages_size = DT_PROP(n, erase_block_size),
#else
#define SIWX917_PAGE_LAYOUT_FLASH_INIT(n)
#endif

#define SIWX917_FLASH_INIT_P(n, p)                                                                 \
	static const struct siwx917_config flash_siwx917_config_##p = {                            \
		.base_address = DT_REG_ADDR(n),                                                    \
		.size = DT_REG_SIZE(n),                                                            \
		.write_block_size = DT_PROP(n, write_block_size),                                  \
		.erase_block_size = DT_PROP(n, erase_block_size),                                  \
		.flash_parameters.write_block_size = DT_PROP(n, write_block_size),                 \
		.flash_parameters.erase_value = 0xff,                                              \
		SIWX917_PAGE_LAYOUT_FLASH_INIT(n)                                                  \
	};                                                \
	static struct siwx917_data flash_siwx917_data_##p = {                                      \
		.lock = Z_SEM_INITIALIZER(flash_siwx917_data_##p.lock, 1, 1),                      \
	};                                                                                         \
	DEVICE_DT_INST_DEFINE(p, flash_siwx917_init, NULL, &flash_siwx917_data_##p,                \
			      &flash_siwx917_config_##p, POST_KERNEL, CONFIG_FLASH_INIT_PRIORITY,  \
			      &siwx917_api);

#define SIWX917_FLASH_INIT(p)                                                                      \
	BUILD_ASSERT(DT_INST_CHILD_NUM_STATUS_OKAY(p) == 1);                                       \
	DT_INST_FOREACH_CHILD_STATUS_OKAY_VARGS(p, SIWX917_FLASH_INIT_P, p)

DT_INST_FOREACH_STATUS_OKAY(SIWX917_FLASH_INIT)
