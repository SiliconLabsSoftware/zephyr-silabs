/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(hid_mouse, LOG_LEVEL_INF);

#include <zephyr/sys/util.h>

#include "hid_mouse.h"

#define HID_USAGE_PAGE_GENERIC_DESKTOP 0x01
#define HID_USAGE_PAGE_BUTTON          0x09

#define HID_USAGE_GENERIC_MOUSE   0x02
#define HID_USAGE_GENERIC_POINTER 0x01
#define HID_USAGE_GENERIC_X       0x30
#define HID_USAGE_GENERIC_Y       0x31

#define HID_MAIN_ITEM_INPUT          0x80
#define HID_MAIN_ITEM_COLLECTION     0xA0
#define HID_MAIN_ITEM_END_COLLECTION 0xC0

#define HID_GLOBAL_USAGE_PAGE      0x04
#define HID_GLOBAL_LOGICAL_MINIMUM 0x14
#define HID_GLOBAL_LOGICAL_MAXIMUM 0x24
#define HID_GLOBAL_REPORT_SIZE     0x74
#define HID_GLOBAL_REPORT_ID       0x84
#define HID_GLOBAL_REPORT_COUNT    0x94
#define HID_GLOBAL_PUSH            0xA4
#define HID_GLOBAL_POP             0xB4

#define HID_LOCAL_USAGE         0x08
#define HID_LOCAL_USAGE_MINIMUM 0x18
#define HID_LOCAL_USAGE_MAXIMUM 0x28

#define HID_INPUT_CONSTANT         BIT(0)
#define HID_INPUT_VARIABLE         BIT(1)
#define HID_INPUT_RELATIVE         BIT(2)
#define HID_COLLECTION_APPLICATION 0x01
#define HID_COLLECTION_MAX_DEPTH   8U

struct hid_parse_state {
	uint16_t usage_page;
	int32_t logical_min;
	int32_t logical_max;
	uint32_t report_size;
	uint32_t report_count;
	uint8_t report_id;
	bool has_report_id;

	uint32_t usages[16];
	uint8_t usage_count;
	uint32_t usage_min;
	uint32_t usage_max;
	bool has_usage_min;
	bool has_usage_max;

	uint16_t bit_offset[256];
	bool mouse_collection[HID_COLLECTION_MAX_DEPTH];
	size_t collection_depth;
};

static uint32_t mask_for_size(uint8_t bits)
{
	if (bits >= 32U) {
		return UINT32_MAX;
	}

	return BIT_MASK(bits);
}

static int32_t sign_extend_value(uint32_t value, uint8_t bits)
{
	uint32_t sign_bit;

	if ((bits == 0U) || (bits >= 32U)) {
		return (int32_t)value;
	}

	sign_bit = BIT(bits - 1U);
	if ((value & sign_bit) == 0U) {
		return (int32_t)value;
	}

	value |= ~mask_for_size(bits);
	return (int32_t)value;
}

static uint32_t get_bits(const uint8_t *buf, size_t len, uint16_t bit_offset, uint8_t bit_size)
{
	uint32_t value = 0U;

	if (bit_size > 32U) {
		bit_size = 32U;
	}

	for (uint8_t i = 0U; i < bit_size; i++) {
		uint16_t bit = bit_offset + i;

		if ((bit / 8U) >= len) {
			break;
		}

		if ((buf[bit / 8U] & BIT(bit % 8U)) != 0U) {
			value |= BIT(i);
		}
	}

	return value;
}

static int32_t hid_item_value(const uint8_t *data, uint8_t size)
{
	switch (size) {
	case 0:
		return 0;
	case 1:
		return (int8_t)data[0];
	case 2:
		return (int16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
	case 4:
		return (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8) |
				 ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));
	default:
		return 0;
	}
}

static uint32_t hid_item_uvalue(const uint8_t *data, uint8_t size)
{
	switch (size) {
	case 0:
		return 0U;
	case 1:
		return data[0];
	case 2:
		return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
	case 4:
		return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
		       ((uint32_t)data[3] << 24);
	default:
		return 0U;
	}
}

static void clear_local_items(struct hid_parse_state *st)
{
	st->usage_count = 0U;
	st->usage_min = 0U;
	st->usage_max = 0U;
	st->has_usage_min = false;
	st->has_usage_max = false;
}

static uint32_t usage_for_index(const struct hid_parse_state *st, uint32_t index)
{
	if (index < st->usage_count) {
		return st->usages[index];
	}

	if (st->has_usage_min && st->has_usage_max && st->usage_min <= st->usage_max &&
	    index <= st->usage_max - st->usage_min) {
		return st->usage_min + index;
	}

	if (st->usage_count > 0U) {
		return st->usages[st->usage_count - 1U];
	}

	return 0U;
}

static void set_field(struct hid_mouse_field *field, uint16_t bit_offset, uint8_t bit_size,
		      bool is_signed)
{
	if (field->valid) {
		return;
	}

	field->valid = true;
	field->bit_offset = bit_offset;
	field->bit_size = bit_size;
	field->is_signed = is_signed;
}

static bool parser_complete(const struct hid_mouse_parser *parser)
{
	return parser->left_button.valid && parser->right_button.valid && parser->x.valid &&
	       parser->y.valid;
}

static void maybe_set_report_id(struct hid_mouse_parser *parser, const struct hid_parse_state *st)
{
	if (!parser->valid) {
		parser->has_report_id = st->has_report_id;
		parser->report_id = st->report_id;
	}
}

static bool parser_has_any_field(const struct hid_mouse_parser *parser)
{
	return parser->left_button.valid || parser->right_button.valid || parser->x.valid ||
	       parser->y.valid;
}

static bool report_id_matches_parser(const struct hid_mouse_parser *parser,
				     const struct hid_parse_state *st)
{
	if (!parser_has_any_field(parser)) {
		return true;
	}

	return parser->has_report_id == st->has_report_id && parser->report_id == st->report_id;
}

static int parse_input_item(struct hid_mouse_parser *parser, struct hid_parse_state *st,
			    uint32_t input_flags)
{
	uint16_t *bit_offset = &st->bit_offset[st->report_id];
	bool is_constant = (input_flags & HID_INPUT_CONSTANT) != 0U;
	bool is_signed = st->logical_min < 0;
	bool in_mouse =
		st->collection_depth != 0U && st->mouse_collection[st->collection_depth - 1U];
	uint32_t item_bits;

	if (st->report_size == 0U || st->report_count == 0U ||
	    st->report_size > UINT16_MAX / st->report_count) {
		return -EMSGSIZE;
	}
	item_bits = st->report_size * st->report_count;
	if (item_bits > (uint32_t)UINT16_MAX - *bit_offset) {
		return -EMSGSIZE;
	}

	if (in_mouse && !is_constant && (input_flags & HID_INPUT_VARIABLE) != 0U &&
	    st->report_size <= 32U && report_id_matches_parser(parser, st)) {
		for (uint32_t i = 0U; i < st->report_count; i++) {
			uint32_t usage = usage_for_index(st, i);
			uint16_t field_offset = *bit_offset + ((uint16_t)i * st->report_size);

			if (st->usage_page == HID_USAGE_PAGE_BUTTON) {
				if (usage == 1U) {
					maybe_set_report_id(parser, st);
					set_field(&parser->left_button, field_offset,
						  st->report_size, false);
				} else if (usage == 2U) {
					maybe_set_report_id(parser, st);
					set_field(&parser->right_button, field_offset,
						  st->report_size, false);
				}
			} else if (st->usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP &&
				   (input_flags & HID_INPUT_RELATIVE) != 0U && is_signed &&
				   st->report_size <= 16U) {
				if (usage == HID_USAGE_GENERIC_X) {
					maybe_set_report_id(parser, st);
					set_field(&parser->x, field_offset, st->report_size,
						  is_signed);
				} else if (usage == HID_USAGE_GENERIC_Y) {
					maybe_set_report_id(parser, st);
					set_field(&parser->y, field_offset, st->report_size,
						  is_signed);
				}
			}
		}
	}

	*bit_offset += item_bits;
	clear_local_items(st);
	return 0;
}

int hid_mouse_parser_init(struct hid_mouse_parser *parser, const uint8_t *report_map,
			  size_t report_map_len)
{
	struct hid_parse_state st;
	struct hid_mouse_parser candidate = {0};
	size_t pos = 0U;
	int err;

	if (parser == NULL) {
		return -EINVAL;
	}

	memset(parser, 0, sizeof(*parser));
	if (report_map == NULL || report_map_len == 0U) {
		return -EINVAL;
	}
	memset(&st, 0, sizeof(st));

	while (pos < report_map_len) {
		uint8_t prefix = report_map[pos++];
		uint8_t size_code;
		uint8_t size;
		uint8_t tag;
		const uint8_t *payload;

		if (prefix == 0xFE) {
			uint8_t long_size;

			if ((pos + 2U) > report_map_len) {
				return -EMSGSIZE;
			}

			long_size = report_map[pos];
			pos += 2U;
			if ((pos + long_size) > report_map_len) {
				return -EMSGSIZE;
			}
			pos += long_size;
			continue;
		}

		size_code = prefix & 0x03U;
		size = (size_code == 3U) ? 4U : size_code;
		tag = prefix & 0xFCU;

		if ((pos + size) > report_map_len) {
			return -EMSGSIZE;
		}

		payload = &report_map[pos];
		pos += size;

		switch (tag) {
		case HID_GLOBAL_USAGE_PAGE:
			st.usage_page = (uint16_t)hid_item_uvalue(payload, size);
			break;
		case HID_GLOBAL_LOGICAL_MINIMUM:
			st.logical_min = hid_item_value(payload, size);
			break;
		case HID_GLOBAL_LOGICAL_MAXIMUM:
			st.logical_max = hid_item_value(payload, size);
			break;
		case HID_GLOBAL_REPORT_SIZE:
			st.report_size = hid_item_uvalue(payload, size);
			break;
		case HID_GLOBAL_REPORT_ID:
			if (hid_item_uvalue(payload, size) == 0U ||
			    hid_item_uvalue(payload, size) > UINT8_MAX) {
				return -ENOTSUP;
			}
			st.report_id = hid_item_uvalue(payload, size);
			st.has_report_id = true;
			break;
		case HID_GLOBAL_REPORT_COUNT:
			st.report_count = hid_item_uvalue(payload, size);
			break;
		case HID_GLOBAL_PUSH:
		case HID_GLOBAL_POP:
			/* This sample does not implement a HID global-state stack. */
			return -ENOTSUP;
		case HID_LOCAL_USAGE:
			if (st.usage_count < ARRAY_SIZE(st.usages)) {
				st.usages[st.usage_count++] = hid_item_uvalue(payload, size);
			}
			break;
		case HID_LOCAL_USAGE_MINIMUM:
			st.usage_min = hid_item_uvalue(payload, size);
			st.has_usage_min = true;
			break;
		case HID_LOCAL_USAGE_MAXIMUM:
			st.usage_max = hid_item_uvalue(payload, size);
			st.has_usage_max = true;
			break;
		case HID_MAIN_ITEM_INPUT:
			err = parse_input_item(&candidate, &st, hid_item_uvalue(payload, size));
			if (err) {
				return err;
			}
			if (parser_complete(&candidate)) {
				candidate.valid = true;
			}
			break;
		case HID_MAIN_ITEM_COLLECTION: {
			bool in_mouse = st.collection_depth != 0U &&
					st.mouse_collection[st.collection_depth - 1U];

			if (st.collection_depth == ARRAY_SIZE(st.mouse_collection)) {
				return -ENOTSUP;
			}
			if (hid_item_uvalue(payload, size) == HID_COLLECTION_APPLICATION) {
				in_mouse = st.usage_page == HID_USAGE_PAGE_GENERIC_DESKTOP &&
					   usage_for_index(&st, 0U) == HID_USAGE_GENERIC_MOUSE;
				if (in_mouse && !candidate.valid) {
					/* Never combine fields from separate mouse applications. */
					memset(&candidate, 0, sizeof(candidate));
				}
			}
			st.mouse_collection[st.collection_depth++] = in_mouse;
			clear_local_items(&st);
			break;
		}
		case HID_MAIN_ITEM_END_COLLECTION:
			if (st.collection_depth == 0U) {
				return -EMSGSIZE;
			}
			st.collection_depth--;
			clear_local_items(&st);
			break;
		default:
			break;
		}
	}

	if (st.collection_depth != 0U) {
		return -EMSGSIZE;
	}
	if (!parser_complete(&candidate)) {
		return -ENOTSUP;
	}

	*parser = candidate;
	parser->valid = true;

	LOG_INF("Report ID      : %d", parser->report_id);
	LOG_INF("Has Report ID  : %d", parser->has_report_id);

	LOG_INF("Buttons: bit %u size %u", parser->left_button.bit_offset,
		parser->left_button.bit_size);

	LOG_INF("Buttons: bit %u size %u", parser->right_button.bit_offset,
		parser->right_button.bit_size);

	LOG_INF("X: bit %u size %u signed %d", parser->x.bit_offset, parser->x.bit_size,
		parser->x.is_signed);

	LOG_INF("Y: bit %u size %u signed %d", parser->y.bit_offset, parser->y.bit_size,
		parser->y.is_signed);

	return 0;
}

int hid_mouse_decode_report(const struct hid_mouse_parser *parser, const uint8_t *data,
			    size_t length, struct mouse_data_element *mouse_data)
{
	uint32_t x_raw;
	uint32_t y_raw;
	uint16_t required_bits;

	if ((parser == NULL) || (data == NULL) || (mouse_data == NULL)) {
		return -EINVAL;
	}

	if (!parser->valid) {
		return -ENOTSUP;
	}

	if (length == 0U) {
		return -EMSGSIZE;
	}

	/*
	 * A HID over GATT Report characteristic contains the report body only.
	 * Its Report Reference descriptor carries the report ID, so byte zero is
	 * always report data.  In particular, a button byte of 0x02 must not be
	 * mistaken for report ID 2.
	 */
	required_bits = MAX(parser->x.bit_offset + parser->x.bit_size,
			    parser->y.bit_offset + parser->y.bit_size);
	required_bits =
		MAX(required_bits, parser->left_button.bit_offset + parser->left_button.bit_size);
	required_bits =
		MAX(required_bits, parser->right_button.bit_offset + parser->right_button.bit_size);
	if (length < DIV_ROUND_UP(required_bits, 8U)) {
		return -EMSGSIZE;
	}

	memset(mouse_data, 0, sizeof(*mouse_data));

	if (parser->left_button.valid) {
		mouse_data->left_button = get_bits(data, length, parser->left_button.bit_offset,
						   parser->left_button.bit_size) != 0U;
	}

	if (parser->right_button.valid) {
		mouse_data->right_button = get_bits(data, length, parser->right_button.bit_offset,
						    parser->right_button.bit_size) != 0U;
	}

	if (!parser->x.valid || !parser->y.valid) {
		return -ENODATA;
	}

	x_raw = get_bits(data, length, parser->x.bit_offset, parser->x.bit_size);

	y_raw = get_bits(data, length, parser->y.bit_offset, parser->y.bit_size);

	mouse_data->dx = parser->x.is_signed ? (int16_t)sign_extend_value(x_raw, parser->x.bit_size)
					     : (int16_t)x_raw;

	mouse_data->dy = parser->y.is_signed ? (int16_t)sign_extend_value(y_raw, parser->y.bit_size)
					     : (int16_t)y_raw;

	return 0;
}
