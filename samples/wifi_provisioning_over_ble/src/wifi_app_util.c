/* SPDX-License-Identifier: Apache-2.0 */
/* SPDX-FileCopyrightText: 2025 Silicon Laboratories Inc. */

#include "wifi_app_util.h"

uint8_t wifi_app_map_security_to_siconnect(enum wifi_security_type security)
{
	uint8_t code = 0xFF; /* Unknown */

	switch (security) {
	case WIFI_SECURITY_TYPE_NONE:
		code = WIFI_APP_SEC_CODE_OPEN;
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		code = WIFI_APP_SEC_CODE_WPA;
		break;
	case WIFI_SECURITY_TYPE_PSK:
	case WIFI_SECURITY_TYPE_PSK_SHA256:
	case WIFI_SECURITY_TYPE_FT_PSK:
		code = WIFI_APP_SEC_CODE_WPA2_PSK;
		break;
	case WIFI_SECURITY_TYPE_WEP:
		code = WIFI_APP_SEC_CODE_WEP;
		break;
	case WIFI_SECURITY_TYPE_EAP:
	case WIFI_SECURITY_TYPE_EAP_PEAP_MSCHAPV2:
	case WIFI_SECURITY_TYPE_EAP_PEAP_GTC:
	case WIFI_SECURITY_TYPE_EAP_TTLS_MSCHAPV2:
	case WIFI_SECURITY_TYPE_EAP_PEAP_TLS:
	case WIFI_SECURITY_TYPE_FT_EAP:
		code = WIFI_APP_SEC_CODE_WPA2_EAP;
		break;
	case WIFI_SECURITY_TYPE_FT_EAP_SHA384:
		code = WIFI_APP_SEC_CODE_WPA3_EAP;
		break;
	case WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL:
		code = WIFI_APP_SEC_CODE_WPA_WPA2_MIXED;
		break;
	case WIFI_SECURITY_TYPE_SAE_AUTO:
		code = WIFI_APP_SEC_CODE_WPA3_TRANSITION;
		break;
	case WIFI_SECURITY_TYPE_SAE:
	case WIFI_SECURITY_TYPE_SAE_H2E:
	case WIFI_SECURITY_TYPE_FT_SAE:
		code = WIFI_APP_SEC_CODE_WPA3;
		break;
	default:
		code = 0xFF;
		break;
	}
	return code;
}

enum wifi_security_type wifi_app_map_security_from_siconnect(uint8_t app_code)
{
	enum wifi_security_type security = WIFI_SECURITY_TYPE_UNKNOWN;

	/* Compat: treat 3 (from some app builds), 7 and 8 as WPA3 (SAE_AUTO) */
	switch (app_code) {
	case WIFI_APP_SEC_CODE_OPEN:
		security = WIFI_SECURITY_TYPE_NONE;
		break;
	case WIFI_APP_SEC_CODE_WPA:
		security = WIFI_SECURITY_TYPE_WPA_PSK;
		break;
	case WIFI_APP_SEC_CODE_WPA2_PSK:
		security = WIFI_SECURITY_TYPE_PSK;
		break;
	case WIFI_APP_SEC_CODE_WEP:
		security = WIFI_SECURITY_TYPE_SAE_AUTO; /* prefer WPA3 over WEP for app interop */
		break;
	/* No explicit code 4 in our map; keep 5 as EAP for older apps */
	case WIFI_APP_SEC_CODE_WPA2_EAP:
		security = WIFI_SECURITY_TYPE_EAP;
		break;
	case WIFI_APP_SEC_CODE_WPA_WPA2_MIXED:
		security = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
		break;
	case WIFI_APP_SEC_CODE_WPA3:
	case WIFI_APP_SEC_CODE_WPA3_TRANSITION:
		security = WIFI_SECURITY_TYPE_SAE_AUTO;
		break;
	case WIFI_APP_SEC_CODE_WPA3_EAP:
	case WIFI_APP_SEC_CODE_WPA3_EAP_192:
		security = WIFI_SECURITY_TYPE_FT_EAP_SHA384;
		break;
	default:
		security = WIFI_SECURITY_TYPE_UNKNOWN;
		break;
	}
	return security;
}
