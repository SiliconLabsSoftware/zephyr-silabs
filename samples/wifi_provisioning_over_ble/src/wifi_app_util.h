/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2025 Silicon Laboratories Inc. */

#pragma once

#include <zephyr/net/wifi.h>
#include <stdint.h>

/* Si-Connect app security code values */
#define WIFI_APP_SEC_CODE_OPEN            0
#define WIFI_APP_SEC_CODE_WPA             1
#define WIFI_APP_SEC_CODE_WPA2_PSK        2
#define WIFI_APP_SEC_CODE_WEP             3
#define WIFI_APP_SEC_CODE_WPA2_EAP        5
#define WIFI_APP_SEC_CODE_WPA_WPA2_MIXED  6
#define WIFI_APP_SEC_CODE_WPA3            7
#define WIFI_APP_SEC_CODE_WPA3_TRANSITION 8
#define WIFI_APP_SEC_CODE_WPA3_EAP        9
#define WIFI_APP_SEC_CODE_WPA3_EAP_192    10

/* Maps Zephyr security enum to Si-Connect app codes. */
uint8_t wifi_app_map_security_to_siconnect(enum wifi_security_type security);

/* Maps Si-Connect app codes to Zephyr security enum. */
enum wifi_security_type wifi_app_map_security_from_siconnect(uint8_t app_code);
