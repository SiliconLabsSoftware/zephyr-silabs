/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Public sl_zigbee_token API forwards to the prebuilt stack. slx_* token I/O
 * is provided separately by sl_zigbee_token_zephyr_shim.c.
 */

#include "stack/include/sl_zigbee_token.h"
#include "stack/internal/inc/sl_zigbee_token_internal_def.h"

uint32_t sl_zigbee_get_token_count(void)
{
	return sli_zigbee_stack_get_token_count();
}

sl_status_t sl_zigbee_get_token_data(uint32_t token,
				     uint32_t index,
				     sl_zigbee_token_data_t *tokenData)
{
	return sli_zigbee_stack_get_token_data(token, index, tokenData);
}

sl_status_t sl_zigbee_get_token_default(uint32_t token,
					uint8_t *default_token_value)
{
	return sli_zigbee_stack_get_token_default(token, default_token_value);
}

sl_status_t sl_zigbee_get_token_info(uint8_t index,
				     sl_zigbee_token_info_t *tokenInfo)
{
	return sli_zigbee_stack_get_token_info(index, tokenInfo);
}

sl_status_t sl_zigbee_initialize_basic_token(uint32_t token,
					     void *default_token_value,
					     uint32_t token_size)
{
	return sli_zigbee_stack_initialize_basic_token(token,
						       default_token_value,
						       token_size);
}

sl_status_t sl_zigbee_initialize_counter_token(uint32_t token,
					       void *default_token_value,
					       uint32_t token_size)
{
	return sli_zigbee_stack_initialize_counter_token(token,
							 default_token_value,
							 token_size);
}

sl_status_t sl_zigbee_initialize_index_token(uint32_t token_base,
					   void *default_token_value,
					   uint32_t token_size,
					   uint8_t token_index_size)
{
	return sli_zigbee_stack_initialize_index_token(token_base,
						       default_token_value,
						       token_size,
						       token_index_size);
}

sl_status_t sl_zigbee_set_token_data(uint32_t token,
				     uint32_t index,
				     sl_zigbee_token_data_t *tokenData)
{
	return sli_zigbee_stack_set_token_data(token, index, tokenData);
}
