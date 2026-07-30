/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr NVS backend for Silicon Labs Zigbee stack token persistence.
 */

#include <string.h>

#include <zephyr/autoconf.h>
#include <zephyr/devicetree.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/kvss/nvs.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#include "sl_status.h"
#include "stack/include/sl_zigbee_token.h"
#include "stack/internal/inc/sl_zigbee_token_internal_def.h"

LOG_MODULE_REGISTER(silabs_zigbee_token, CONFIG_LOG_DEFAULT_LEVEL);

#if DT_NODE_EXISTS(DT_NODELABEL(zb_token_partition))
#define ZB_TOKEN_NVS_PARTITION		zb_token_partition
#elif DT_NODE_EXISTS(DT_NODELABEL(storage_partition))
#define ZB_TOKEN_NVS_PARTITION		storage_partition
#else
#error "Zigbee token NVS shim requires zb_token_partition or storage_partition"
#endif

#define ZB_TOKEN_NVS_PARTITION_DEVICE	PARTITION_DEVICE(ZB_TOKEN_NVS_PARTITION)
#define ZB_TOKEN_NVS_PARTITION_OFFSET	PARTITION_OFFSET(ZB_TOKEN_NVS_PARTITION)

struct zb_token_nvs_hdr {
	uint32_t token;
	uint32_t length;
};

static struct nvs_fs zb_token_nvs;
static struct k_mutex zb_token_mutex;
static bool zb_token_nvs_ready;

static uint16_t zb_token_to_nvs_id(uint32_t token)
{
	return (uint16_t)(token ^ (token >> 16));
}

static sl_status_t zb_token_nvs_mount(void)
{
	const struct device *flash_dev = ZB_TOKEN_NVS_PARTITION_DEVICE;
	struct flash_pages_info page_info;
	int rc;

	if (zb_token_nvs_ready) {
		return SL_STATUS_OK;
	}

	if (!device_is_ready(flash_dev)) {
		LOG_ERR("flash device for storage_partition is not ready");
		return SL_STATUS_FAIL;
	}

	zb_token_nvs.flash_device = flash_dev;
	zb_token_nvs.offset = ZB_TOKEN_NVS_PARTITION_OFFSET;

	rc = flash_get_page_info_by_offs(flash_dev, zb_token_nvs.offset, &page_info);
	if (rc != 0) {
		LOG_ERR("flash_get_page_info_by_offs failed: %d", rc);
		return SL_STATUS_FAIL;
	}

	zb_token_nvs.sector_size = page_info.size;
	zb_token_nvs.sector_count = CONFIG_SILABS_ZIGBEE_TOKEN_NVS_SECTOR_COUNT;

	rc = nvs_mount(&zb_token_nvs);
	if (rc != 0) {
		LOG_ERR("nvs_mount failed: %d", rc);
		return SL_STATUS_FAIL;
	}

	zb_token_nvs_ready = true;
	LOG_INF("mounted Zigbee token NVS on %s (offset 0x%lx, %u x %u bytes)",
		flash_dev->name, (unsigned long)zb_token_nvs.offset,
		zb_token_nvs.sector_count, zb_token_nvs.sector_size);

	return SL_STATUS_OK;
}

static sl_status_t zb_token_nvs_read(uint32_t token, void *data, uint32_t length)
{
	uint8_t buf[sizeof(struct zb_token_nvs_hdr) + CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE];
	struct zb_token_nvs_hdr *hdr = (struct zb_token_nvs_hdr *)buf;
	ssize_t stored;
	uint16_t nvs_id = zb_token_to_nvs_id(token);

	if (length == 0U || length > CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE || data == NULL) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	stored = nvs_read(&zb_token_nvs, nvs_id, buf, sizeof(buf));
	if (stored < (ssize_t)sizeof(*hdr)) {
		return SL_STATUS_NOT_FOUND;
	}

	if (hdr->token != token) {
		LOG_WRN("NVS id collision for token 0x%08x (stored 0x%08x)", token, hdr->token);
		return SL_STATUS_NOT_FOUND;
	}

	if (hdr->length != length) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	if (stored < (ssize_t)(sizeof(*hdr) + length)) {
		return SL_STATUS_FAIL;
	}

	memcpy(data, buf + sizeof(*hdr), length);
	return SL_STATUS_OK;
}

static sl_status_t zb_token_nvs_write(uint32_t token, const void *data, uint32_t length)
{
	uint8_t buf[sizeof(struct zb_token_nvs_hdr) + CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE];
	struct zb_token_nvs_hdr *hdr = (struct zb_token_nvs_hdr *)buf;
	ssize_t written;
	uint16_t nvs_id = zb_token_to_nvs_id(token);

	if (length == 0U || length > CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE || data == NULL) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	hdr->token = token;
	hdr->length = length;
	memcpy(buf + sizeof(*hdr), data, length);

	written = nvs_write(&zb_token_nvs, nvs_id, buf, sizeof(*hdr) + length);
	if (written < 0) {
		LOG_ERR("nvs_write failed for token 0x%08x: %d", token, (int)written);
		return SL_STATUS_FAIL;
	}

	return SL_STATUS_OK;
}

static int zb_token_nvs_sys_init(void)
{
	k_mutex_init(&zb_token_mutex);
	return 0;
}

SYS_INIT(zb_token_nvs_sys_init, POST_KERNEL, 0);

sl_status_t halStackInitTokens(void)
{
	k_mutex_lock(&zb_token_mutex, K_FOREVER);
	sl_status_t status = zb_token_nvs_mount();
	k_mutex_unlock(&zb_token_mutex);

	return status;
}

sl_status_t slx_zigbee_token_manager_get_data(uint32_t token, void *data, uint32_t length)
{
	sl_status_t status;

	k_mutex_lock(&zb_token_mutex, K_FOREVER);
	status = zb_token_nvs_mount();
	if (status == SL_STATUS_OK) {
		status = zb_token_nvs_read(token, data, length);
	}
	k_mutex_unlock(&zb_token_mutex);

	return status;
}

sl_status_t slx_zigbee_token_manager_set_data(uint32_t token, void *data, uint32_t length)
{
	sl_status_t status;

	k_mutex_lock(&zb_token_mutex, K_FOREVER);
	status = zb_token_nvs_mount();
	if (status == SL_STATUS_OK) {
		status = zb_token_nvs_write(token, data, length);
	}
	k_mutex_unlock(&zb_token_mutex);

	return status;
}

sl_status_t slxi_zigbee_stack_token_manager_get_data(uint32_t token, void *data, uint32_t length)
{
	return slx_zigbee_token_manager_get_data(token, data, length);
}

sl_status_t sl_token_manager_increment_counter(uint32_t token)
{
	uint32_t value = 0U;
	sl_status_t status;

	k_mutex_lock(&zb_token_mutex, K_FOREVER);

	status = zb_token_nvs_mount();
	if (status != SL_STATUS_OK) {
		goto out;
	}

	status = zb_token_nvs_read(token, &value, sizeof(value));
	if (status != SL_STATUS_OK && status != SL_STATUS_NOT_FOUND) {
		goto out;
	}

	value++;
	status = zb_token_nvs_write(token, &value, sizeof(value));

out:
	k_mutex_unlock(&zb_token_mutex);
	return status;
}
