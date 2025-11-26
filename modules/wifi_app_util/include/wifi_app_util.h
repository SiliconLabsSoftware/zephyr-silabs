/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <zephyr/net/wifi.h>
#include <stdint.h>

/* Maps Zephyr security enum to Si-Connect app codes. */
uint8_t wifi_app_map_security_to_siconnect(enum wifi_security_type security);

/* Maps Si-Connect app codes to Zephyr security enum. */
enum wifi_security_type wifi_app_map_security_from_siconnect(uint8_t app_code);


