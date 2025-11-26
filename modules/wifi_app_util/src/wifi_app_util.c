/* SPDX-License-Identifier: Apache-2.0 */

#include <zephyr/net/wifi.h>
#include <stdint.h>

uint8_t wifi_app_map_security_to_siconnect(enum wifi_security_type security)
{
	uint8_t code = 0xFF; /* Unknown */

	switch (security) {
	case WIFI_SECURITY_TYPE_NONE:
		code = 0; /* OPEN */
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		code = 1; /* WPA */
		break;
	case WIFI_SECURITY_TYPE_PSK:
	case WIFI_SECURITY_TYPE_PSK_SHA256:
	case WIFI_SECURITY_TYPE_FT_PSK:
		code = 2; /* WPA2 */
		break;
	case WIFI_SECURITY_TYPE_WEP:
		code = 3; /* WEP */
		break;
	case WIFI_SECURITY_TYPE_EAP:
	case WIFI_SECURITY_TYPE_EAP_PEAP_MSCHAPV2:
	case WIFI_SECURITY_TYPE_EAP_PEAP_GTC:
	case WIFI_SECURITY_TYPE_EAP_TTLS_MSCHAPV2:
	case WIFI_SECURITY_TYPE_EAP_PEAP_TLS:
	case WIFI_SECURITY_TYPE_FT_EAP:
		code = 5; /* WPA2 Enterprise */
		break;
	case WIFI_SECURITY_TYPE_FT_EAP_SHA384:
		code = 9; /* WPA3 Enterprise */
		break;
	case WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL:
		code = 6; /* WPA/WPA2 Mixed */
		break;
	case WIFI_SECURITY_TYPE_SAE_AUTO:
		code = 8; /* WPA3 Transition */
		break;
	case WIFI_SECURITY_TYPE_SAE:
	case WIFI_SECURITY_TYPE_SAE_H2E:
	case WIFI_SECURITY_TYPE_FT_SAE:
		code = 7; /* WPA3 */
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
	case 0:
		security = WIFI_SECURITY_TYPE_NONE;
		break;
	case 1:
		security = WIFI_SECURITY_TYPE_WPA_PSK;
		break;
	case 2:
		security = WIFI_SECURITY_TYPE_PSK;
		break;
	case 3:
		security = WIFI_SECURITY_TYPE_SAE_AUTO; /* prefer WPA3 over WEP for app interop */
		break;
	case 4:
	case 5:
		security = WIFI_SECURITY_TYPE_EAP;
		break;
	case 6:
		security = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
		break;
	case 7:
	case 8:
		security = WIFI_SECURITY_TYPE_SAE_AUTO;
		break;
	case 9:
	case 10:
		security = WIFI_SECURITY_TYPE_FT_EAP_SHA384;
		break;
	default:
		security = WIFI_SECURITY_TYPE_UNKNOWN;
		break;
	}
	return security;
}


