/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef HID_MOUSE_H_
#define HID_MOUSE_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "app_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct hid_mouse_field {
	bool valid;
	uint16_t bit_offset;
	uint8_t bit_size;
	bool is_signed;
};

struct hid_mouse_parser {
	bool valid;
	bool has_report_id;
	uint8_t report_id;

	struct hid_mouse_field left_button;
	struct hid_mouse_field right_button;
	struct hid_mouse_field x;
	struct hid_mouse_field y;
};

int hid_mouse_parser_init(struct hid_mouse_parser *parser, const uint8_t *report_map,
			  size_t report_map_len);

int hid_mouse_decode_report(const struct hid_mouse_parser *parser, const uint8_t *data,
			    size_t length, struct mouse_data_element *mouse_data);

#ifdef __cplusplus
}
#endif

#endif /* HID_MOUSE_H_ */
