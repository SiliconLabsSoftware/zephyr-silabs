/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr CTM glue (stock layering):
 *   sl_token_manager_*          → thin dispatch (stand-in for api.c)
 *   sli_token_manager_*_static_* → stock manufacturing.c
 *   sli_token_manager_*_dynamic_* → this file (NVS instead of NVM3)
 *
 * One lock: sl_token_manager_lock_* (NVS has no internal lock like NVM3).
 */

#include <string.h>

#include <zephyr/autoconf.h>
#include <zephyr/devicetree.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/kvss/nvs.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#include "sl_status.h"
#include "sl_token_manager_api.h"
#include "sl_token_manager_defines.h"
#include "sl_token_manager_lock.h"
#include "sli_token_manager_internal.h"

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

/*
 * Stock CTM puts these in api.c / internal.c. Provide the Series-2 subset
 * here so we can skip internal.c (preinit + NVM3 key-space helpers).
 */
bool sl_token_manager_init_success;

sl_token_type_t sli_token_manager_decode_token_type(uint32_t token)
{
	if ((token & SL_TOKEN_DYNAMIC_MASK) == SL_TOKEN_TYPE_NVM3) {
		return SL_TOKEN_TYPE_NVM3_DEFAULT;
	}
	if ((token & SL_TOKEN_DYNAMIC_MASK) == SL_TOKEN_TYPE_NVM3_SECONDARY) {
		return SL_TOKEN_TYPE_NVM3_ZWAVE;
	}
	if ((token & SL_TOKEN_STATIC_MASK) == SL_TOKEN_TYPE_STATIC_DEVICE) {
		return SL_TOKEN_TYPE_STATIC_DEVICE_TOKEN;
	}
	if ((token & SL_TOKEN_STATIC_MASK) == SL_TOKEN_TYPE_STATIC_SECURE) {
		return SL_TOKEN_TYPE_STATIC_SECURE_TOKEN;
	}

	return SL_TOKEN_TYPE_INVALID;
}

static struct nvs_fs zb_token_nvs;
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
		LOG_ERR("flash device for Zigbee token partition is not ready");
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

static sl_status_t zb_token_nvs_read(uint32_t token, void *data, uint32_t offset, uint32_t length)
{
	uint8_t buf[sizeof(struct zb_token_nvs_hdr) + CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE];
	struct zb_token_nvs_hdr *hdr = (struct zb_token_nvs_hdr *)buf;
	ssize_t stored;
	uint16_t nvs_id = zb_token_to_nvs_id(token);

	if (length == 0U || data == NULL ||
	    (offset + length) > CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE) {
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

	if (hdr->length > CONFIG_SILABS_ZIGBEE_TOKEN_NVS_MAX_SIZE ||
	    (offset + length) > hdr->length) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	if (stored < (ssize_t)(sizeof(*hdr) + hdr->length)) {
		return SL_STATUS_FAIL;
	}

	memcpy(data, buf + sizeof(*hdr) + offset, length);
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

/*
 * Series-2 static writes still call legacy sl_token_set_manufacturing_data().
 * Stub until that path (or an in-tree replacement) is ported.
 */
sl_status_t sl_token_set_manufacturing_data(uint32_t token, void *data, uint32_t length)
{
	ARG_UNUSED(token);
	ARG_UNUSED(data);
	ARG_UNUSED(length);

	return SL_STATUS_NOT_SUPPORTED;
}

/*
 * Dynamic backend (replaces sli_token_manager_dynamic.c / NVM3).
 * Callers must hold sl_token_manager_lock_* .
 */

sl_status_t sli_token_manager_init_dynamic(void)
{
	return zb_token_nvs_mount();
}

sl_status_t sli_token_manager_get_dynamic_data(uint32_t token, void *data, uint32_t offset,
					       uint32_t length)
{
	sl_status_t status = zb_token_nvs_mount();

	if (status == SL_STATUS_OK) {
		status = zb_token_nvs_read(token, data, offset, length);
	}

	return status;
}

sl_status_t sli_token_manager_set_dynamic_data(uint32_t token, void *data, uint32_t length)
{
	sl_status_t status = zb_token_nvs_mount();

	if (status == SL_STATUS_OK) {
		status = zb_token_nvs_write(token, data, length);
	}

	return status;
}

/* ---- Public CTM API (stand-in for sl_token_manager_api.c) ---- */

sl_status_t sl_token_manager_init(void)
{
	sl_status_t status;

	sl_token_manager_lock_begin();

	status = sli_token_manager_init_static();
	if (status != SL_STATUS_OK) {
		goto out;
	}

	status = sli_token_manager_init_dynamic();
	if (status == SL_STATUS_OK) {
		sl_token_manager_init_success = true;
	}

out:
	sl_token_manager_lock_end();
	return status;
}

sl_status_t sl_token_manager_get_data(uint32_t token, void *data, uint32_t length)
{
	sl_status_t status;
	sl_token_type_t type;

	if (!sl_token_manager_init_success) {
		return SL_STATUS_NOT_INITIALIZED;
	}

	type = sli_token_manager_decode_token_type(token);
	switch (type) {
	case SL_TOKEN_TYPE_NVM3_DEFAULT:
	case SL_TOKEN_TYPE_NVM3_ZWAVE:
		sl_token_manager_lock_begin();
		status = sli_token_manager_get_dynamic_data(token, data, 0, length);
		sl_token_manager_lock_end();
		return status;
	case SL_TOKEN_TYPE_STATIC_DEVICE_TOKEN:
	case SL_TOKEN_TYPE_STATIC_SECURE_TOKEN:
		sl_token_manager_lock_begin();
		status = sli_token_manager_get_static_data(token, data, 0, length);
		sl_token_manager_lock_end();
		return status;
	default:
		return SL_STATUS_INVALID_PARAMETER;
	}
}

sl_status_t sl_token_manager_set_data(uint32_t token, void *data, uint32_t length)
{
	sl_status_t status;
	sl_token_type_t type;

	if (!sl_token_manager_init_success) {
		return SL_STATUS_NOT_INITIALIZED;
	}

	type = sli_token_manager_decode_token_type(token);
	switch (type) {
	case SL_TOKEN_TYPE_NVM3_DEFAULT:
	case SL_TOKEN_TYPE_NVM3_ZWAVE:
		sl_token_manager_lock_begin();
		status = sli_token_manager_set_dynamic_data(token, data, length);
		sl_token_manager_lock_end();
		return status;
	case SL_TOKEN_TYPE_STATIC_DEVICE_TOKEN:
	case SL_TOKEN_TYPE_STATIC_SECURE_TOKEN:
		sl_token_manager_lock_begin();
		status = sli_token_manager_set_static_data(token, data, length);
		sl_token_manager_lock_end();
		return status;
	default:
		return SL_STATUS_INVALID_PARAMETER;
	}
}

sl_status_t sl_token_manager_get_partial_data(uint32_t token, void *data, uint32_t offset,
					      uint32_t length)
{
	sl_status_t status;
	sl_token_type_t type;

	if (!sl_token_manager_init_success) {
		return SL_STATUS_NOT_INITIALIZED;
	}

	type = sli_token_manager_decode_token_type(token);
	switch (type) {
	case SL_TOKEN_TYPE_NVM3_DEFAULT:
	case SL_TOKEN_TYPE_NVM3_ZWAVE:
		sl_token_manager_lock_begin();
		status = sli_token_manager_get_dynamic_data(token, data, offset, length);
		sl_token_manager_lock_end();
		return status;
	case SL_TOKEN_TYPE_STATIC_DEVICE_TOKEN:
	case SL_TOKEN_TYPE_STATIC_SECURE_TOKEN:
		sl_token_manager_lock_begin();
		status = sli_token_manager_get_static_data(token, data, offset, length);
		sl_token_manager_lock_end();
		return status;
	default:
		return SL_STATUS_INVALID_PARAMETER;
	}
}

sl_status_t sl_token_manager_delete_dynamic_token(uint32_t token)
{
	sl_token_type_t type;

	if (!sl_token_manager_init_success) {
		return SL_STATUS_NOT_INITIALIZED;
	}

	type = sli_token_manager_decode_token_type(token);
	if (type != SL_TOKEN_TYPE_NVM3_DEFAULT && type != SL_TOKEN_TYPE_NVM3_ZWAVE) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	ARG_UNUSED(token);
	return SL_STATUS_NOT_SUPPORTED;
}

sl_status_t sl_token_manager_increment_counter(uint32_t token)
{
	uint32_t value = 0U;
	sl_status_t status;
	sl_token_type_t type;

	if (!sl_token_manager_init_success) {
		return SL_STATUS_NOT_INITIALIZED;
	}

	type = sli_token_manager_decode_token_type(token);
	if (type != SL_TOKEN_TYPE_NVM3_DEFAULT && type != SL_TOKEN_TYPE_NVM3_ZWAVE) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	sl_token_manager_lock_begin();

	status = zb_token_nvs_mount();
	if (status != SL_STATUS_OK) {
		goto out;
	}

	status = zb_token_nvs_read(token, &value, 0, sizeof(value));
	if (status != SL_STATUS_OK && status != SL_STATUS_NOT_FOUND) {
		goto out;
	}

	if (status == SL_STATUS_NOT_FOUND) {
		value = 0U;
	}

	value++;
	status = zb_token_nvs_write(token, &value, sizeof(value));

out:
	sl_token_manager_lock_end();
	return status;
}

sl_status_t sl_token_manager_get_size(uint32_t token, uint32_t *size_out)
{
	sl_status_t status;
	sl_token_type_t type;

	if (size_out == NULL) {
		return SL_STATUS_INVALID_PARAMETER;
	}

	type = sli_token_manager_decode_token_type(token);
	if (type == SL_TOKEN_TYPE_STATIC_DEVICE_TOKEN ||
	    type == SL_TOKEN_TYPE_STATIC_SECURE_TOKEN) {
		sl_token_manager_lock_begin();
		status = sli_token_manager_get_static_token_size(type, token, size_out);
		sl_token_manager_lock_end();
		return status;
	}

	return SL_STATUS_NOT_SUPPORTED;
}
