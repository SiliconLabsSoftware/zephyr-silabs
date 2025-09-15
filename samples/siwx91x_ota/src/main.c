/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Running this application under net offload mode */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/tls_credentials.h>
#include "firmware_upgradation.h"
#include "sl_wifi.h"

/* Event masks */
#define WIFI_SHELL_MGMT_EVENTS_COMMON                                                              \
	(NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE | NET_EVENT_WIFI_CONNECT_RESULT |   \
	 NET_EVENT_WIFI_DISCONNECT_RESULT)

/* Firmware update configuration */
#define CHUNK_SIZE (10 * 1024) /**< Download chunk size */

/* TLS configuration */
#define TLS_TAG_CA_CERTIFICATE 1 /**< CA certificate security tag */

/* Event flags */
#define WLAN_EVENT_READY     BIT(0)
#define NET_IPV4_EVENT_READY BIT(1)
#define NET_IPV6_EVENT_READY BIT(2)
#define OTA_EVENT_READY      BIT(3)

/* OTA update state machine states */
enum ota_state {
	OTA_STATE_SCAN,           /**< Scan for WiFi networks */
	OTA_STATE_SERVER_CONNECT, /**< Connect to OTA server */
	OTA_STATE_DOWNLOAD        /**< Download and process firmware image */
};

struct http_parse_data {
	char *schema;
	char *host;
	char *path;
	char *port;
	bool is_tls_enabled;
};

struct app_ctx {
	uint16_t scan_result_count;
	enum wifi_security_type security_type;
	struct k_event events;
	struct net_mgmt_event_callback ipv4_mgmt_cb;
	struct net_mgmt_event_callback ipv6_mgmt_cb;
	struct net_mgmt_event_callback wlan_mgmt_cb;
	struct net_mgmt_event_callback dns_mgmt_cb;
	volatile enum ota_state state;
	volatile bool ipv4_addr_config_done;
	volatile bool ipv6_addr_config_done;
	int sock;
	struct http_parse_data http_parse_data_st;
	uint32_t ota_image_size;
	int ota_range_start_byte;
	int ota_range_end_byte;
	int http_status_code;

	/* Flash buffer for firmware chunks */
	uint8_t flash_buffer[1024];
	uint32_t flash_buffer_len;

	/* Separate HTTP receive buffer to avoid conflicts */
	uint8_t http_recv_buffer[1024];

	uint8_t retry_count;
};

static void ota_application_start(struct app_ctx *ctx);
static void ota_wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
					struct net_if *iface);
static void ota_handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb);
static void ota_handle_wifi_connect_result(struct net_mgmt_event_callback *cb);
static void ota_handle_wifi_scan_done(struct net_mgmt_event_callback *cb);
static void ota_handle_wifi_scan_result(struct net_mgmt_event_callback *cb);
static int ota_load_firmware(struct app_ctx *ctx);
static void ota_ipv4_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface);
static void ota_ipv6_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface);
static void ota_cleanup_resources(struct app_ctx *ctx);

static bool ota_compare_firmware_version(struct http_parse_data *http_data)
{
	sl_wifi_firmware_version_t current_version = {};
	char *filename, *dot_pos;
	int current_build_num, ota_build_num;
	int ret;

	ret = sl_wifi_get_firmware_version(&current_version);
	if (ret != SL_STATUS_OK) {
		printf("Failed to get firmware version: 0x%x\n", ret);
		return true;
	}

	current_build_num = current_version.build_num;
	filename = strrchr(http_data->path, '/');
	filename = filename ? filename + 1 : http_data->path;

	dot_pos = strrchr(filename, '.');
	if (dot_pos > filename) {
		dot_pos--;
		while (dot_pos > filename && *dot_pos != '.') {
			dot_pos--;
		}
		if (*dot_pos == '.' && isdigit(*(dot_pos + 1))) {
			ota_build_num = atoi(dot_pos + 1);

			if (current_build_num == ota_build_num) {
				return false;
			} else {
				return true;
			}
		}
	}
	return true;
}

static char *ota_mac_to_string(const uint8_t *mac, uint8_t mac_len, char *buf, size_t buf_len)
{
	if (!mac || mac_len != 6 || !buf || buf_len < 18) {
		return NULL;
	}
	snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
		 mac[4], mac[5]);
	return buf;
}

static char *ota_get_url_field(const char *url, struct http_parser_url parser, int field)
{
	int len = parser.field_data[field].len;
	const char *ptr = url + parser.field_data[field].off;
	char *out;

	/* Return NULL if Port field is not present */
	if (len == 0) {
		return NULL;
	}

	out = strndup(ptr, len);
	return out;
}

/*
 * @brief Parses URL into host, path and port components
 *
 * @param http_parse_data_st Pointer to structure to store the parsed URL components
 * @return 0 on success, negative error code on failure
 */
static int ota_parse_url(struct http_parse_data *http_parse_data_st)
{
	struct http_parser_url parser;
	char *full_url = CONFIG_OTA_UPDATE_URL;
	int ret = 0;

	http_parser_url_init(&parser);
	ret = http_parser_parse_url(full_url, strlen(full_url), 0, &parser);
	__ASSERT(ret == 0, "URL parsing failed");

	/* Get the schema, host, port and path info from the parsed URL */
	__ASSERT(parser.field_set & BIT(UF_SCHEMA), "Schema field missing in URL");
	__ASSERT(parser.field_set & BIT(UF_HOST), "Host field missing in URL");
	__ASSERT(parser.field_set & BIT(UF_PATH), "Path field missing in URL");

	http_parse_data_st->schema = ota_get_url_field(full_url, parser, UF_SCHEMA);
	http_parse_data_st->host = ota_get_url_field(full_url, parser, UF_HOST);
	http_parse_data_st->path = ota_get_url_field(full_url, parser, UF_PATH);
	http_parse_data_st->port = ota_get_url_field(full_url, parser, UF_PORT);

	http_parse_data_st->is_tls_enabled =
		(strcmp(http_parse_data_st->schema, "https") == 0) ? 1 : 0;
	if (http_parse_data_st->port == NULL) {
		http_parse_data_st->port = http_parse_data_st->is_tls_enabled ? "443" : "80";
	}

	printf("Retrieve http%s://%s:%s%s\n", http_parse_data_st->is_tls_enabled ? "s" : "",
	       http_parse_data_st->host, http_parse_data_st->port, http_parse_data_st->path);
	return 0;
}

/*
 * @brief IPv4 event handler for address add/remove events
 *
 * @param cb Pointer to the event callback structure
 * @param mgmt_event The network management event being handled
 * @param iface Network interface that generated the event
 */
static void ota_ipv4_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface)
{
	char addr[INET_ADDRSTRLEN];
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, ipv4_mgmt_cb);

	net_addr_ntop(AF_INET, cb->info, addr, sizeof(addr));
	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		printf("Added IPv4 Address: %s\n", addr);
		ctx->ipv4_addr_config_done = true;
		k_event_post(&ctx->events, NET_IPV4_EVENT_READY);
	} else {
		ctx->ipv4_addr_config_done = false;
		printf("Removed IPv4 Address: %s\n", addr);
		ctx->state = OTA_STATE_SCAN;
		ota_cleanup_resources(ctx);
	}
}

/*
 * @brief IPv6 event handler for address add/remove events
 *
 * @param cb Pointer to the event callback structure
 * @param event The network event to handle
 * @param iface Network interface that generated the event
 */
static void ota_ipv6_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface)
{
	char addr[INET6_ADDRSTRLEN];
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, ipv6_mgmt_cb);

	net_addr_ntop(AF_INET6, cb->info, addr, sizeof(addr));
	if (mgmt_event == NET_EVENT_IPV6_ADDR_ADD) {
		printf("Added IPv6 Address: %s\n", addr);
		k_event_post(&ctx->events, NET_IPV6_EVENT_READY);
	} else {
		printf("Removed IPv6 Address: %s\n", addr);
		ctx->state = OTA_STATE_SCAN;
		ota_cleanup_resources(ctx);
	}
}

static void ota_dns_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				  struct net_if *iface)
{
	const struct sockaddr *entry = cb->info;
	char addr[INET6_ADDRSTRLEN];
	const char *op;

	if (mgmt_event == NET_EVENT_DNS_SERVER_ADD) {
		op = "Added";
	} else {
		op = "Deleted";
	}
	if (entry->sa_family == AF_INET) {
		net_addr_ntop(AF_INET, &net_sin(entry)->sin_addr, addr, sizeof(addr));
	} else if (entry->sa_family == AF_INET6) {
		net_addr_ntop(AF_INET6, &net_sin6(entry)->sin6_addr, addr, sizeof(addr));
	} else {
		strcpy(addr, "<unknown format>");
	}
	printf("%s DNS Address: %s\n", op, addr);
}

static void ota_handle_wifi_scan_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_scan_result *entry = (const struct wifi_scan_result *)cb->info;
	uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];
	uint8_t ssid_print[WIFI_SSID_MAX_LEN + 1];
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	if (strncmp(entry->ssid, CONFIG_OTA_WIFI_SSID, entry->ssid_length) == 0) {
		ctx->security_type = entry->security;
	}

	if (!ctx->scan_result_count) {
		printf("%-4s | %-32s %-5s | %-13s | %-4s | %-15s | %-17s | %-8s\n", "Num", "SSID",
		       "(len)", "Chan (Band)", "RSSI", "Security", "BSSID", "MFP");
	}

	strncpy(ssid_print, entry->ssid, sizeof(ssid_print) - 1);
	ssid_print[sizeof(ssid_print) - 1] = '\0';

	printf("%-4d | %-32s %-5u | %-4u (%-6s) | %-4d | %-15s | %-17s | %-8s\n",
	       ++ctx->scan_result_count, ssid_print, entry->ssid_length, entry->channel,
	       wifi_band_txt(entry->band), entry->rssi, wifi_security_txt(entry->security),
	       ((entry->mac_length) ? ota_mac_to_string(entry->mac, WIFI_MAC_ADDR_LEN,
							mac_string_buf, sizeof(mac_string_buf))
				    : ""),
	       wifi_mfp_txt(entry->mfp));
}

static void ota_handle_wifi_scan_done(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	ctx->scan_result_count = 0;
	if (status->status) {
		printf("Scan request failed (%d)\n", status->status);
	} else {
		k_event_post(&ctx->events, WLAN_EVENT_READY);
	}
}

static void ota_handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	if (status->status) {
		printf("Connection request failed\n");
	} else {
		printf("Connected to Wi-Fi\n");
		k_event_post(&ctx->events, WLAN_EVENT_READY);
	}
}

static void ota_handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	if (status->status) {
		printf("Disconnection request failed (%d)\n", status->status);
	} else {
		printf("Disconnection reason: %d\n", status->disconn_reason);

		/* Set state to scan/reconnect for any disconnect during OTA */
		if (ctx->state > OTA_STATE_SCAN) {
			printf("WiFi disconnected during OTA update, initiating reconnection\n");
			ota_cleanup_resources(ctx);
			ctx->state = OTA_STATE_SCAN;
		}
		k_event_post(&ctx->events, WLAN_EVENT_READY);
	}
}

static void ota_wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
					struct net_if *iface)
{

	switch (mgmt_event) {
	case NET_EVENT_WIFI_SCAN_RESULT:
		ota_handle_wifi_scan_result(cb);
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		ota_handle_wifi_scan_done(cb);
		break;
	case NET_EVENT_WIFI_CONNECT_RESULT:
		ota_handle_wifi_connect_result(cb);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		ota_handle_wifi_disconnect_result(cb);
		break;
	default:
		break;
	}
}

static int ota_wifi_start_scan(struct app_ctx *ctx)
{
	int ret;
	struct wifi_scan_params params = {};
	struct net_if *iface = net_if_get_first_wifi();

	ret = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &params, sizeof(params));
	if (ret) {
		return ret;
	}
	if (k_event_wait_safe(&ctx->events, WLAN_EVENT_READY, false, K_MSEC(30000)) == 0) {
		printf("WiFi scan failed or timed out\n");
		return -errno;
	}
	return 0;
}

/*
 * @brief Connect to WiFi network
 *
 * @param ssid Network SSID
 * @param pwd Network password
 * @param ctx App context pointer
 * @return int 0 on success, negative error code on failure
 */
static int ota_wifi_connect(const char *ssid, const char *pwd, struct app_ctx *ctx)
{
	int ret;
	struct net_if *iface = net_if_get_first_wifi();
	struct wifi_connect_req_params cnx_params = {
		.channel = WIFI_CHANNEL_ANY,
		.band = 0,
		.security = ctx->security_type,
		.psk_length = strlen(pwd),
		.psk = (uint8_t *)pwd,
		.ssid_length = strlen(ssid),
		.ssid = (uint8_t *)ssid
	};

	if (!ssid || !pwd) {
		printf("Invalid connection parameters\n");
		return -EINVAL;
	}

	printf("Connecting to network: %s\n", ssid);
	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cnx_params,
		       sizeof(struct wifi_connect_req_params));
	if (ret) {
		printf("Connection request failed with error: %d\n", ret);
		return ret;
	}
	if (k_event_wait_safe(&ctx->events, WLAN_EVENT_READY, false, K_MSEC(30000)) == 0) {
		return -errno;
	}
	return 0;
}

/*
 * @brief Wait for IP configuration to complete
 * @param ctx Pointer to application context structure
 * @return int 0 on success, negative error code on failure
 */
static int ota_wait_for_ip_config(struct app_ctx *ctx)
{
	int ret;

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		ret = k_event_wait_safe(&ctx->events, NET_IPV4_EVENT_READY, false, K_SECONDS(30));
	} else {
		ret = k_event_wait_safe(&ctx->events, NET_IPV6_EVENT_READY, false, K_SECONDS(30));
	}
	if (!ret && IS_ENABLED(CONFIG_NET_IPV6)) {
		ret = k_event_wait_safe(&ctx->events, NET_IPV6_EVENT_READY, false, K_NO_WAIT);
	}
	return (ret > 0) ? 0 : -ETIMEDOUT;
}

/*
 * @brief Connect to OTA server
 *
 * @param ctx Pointer to application context structure
 * @return int 0 on success, negative error code on failure
 */
static int ota_connect_to_server(struct app_ctx *ctx)
{
	int ret;
	struct zsock_addrinfo *res;
	struct http_parse_data http_parse_data_st = ctx->http_parse_data_st;
	int peer_verify = TLS_PEER_VERIFY_NONE;

	ret = zsock_getaddrinfo(http_parse_data_st.host, http_parse_data_st.port, NULL, &res);
	if (ret != 0) {
		printf("Address resolution failed: %d\n", ret);
		return ret;
	}

	if (http_parse_data_st.is_tls_enabled) {
		ctx->sock = zsock_socket(res->ai_family, res->ai_socktype, IPPROTO_TLS_1_2);
		if (ctx->sock < 0) {
			goto error;
		}
		ret = zsock_setsockopt(ctx->sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify,
				       sizeof(peer_verify));

		if (ret < 0) {
			goto error;
		}

		/* NOTE: The customer must not proceed to production with this */
		ret = zsock_setsockopt(ctx->sock, SOL_TLS, TLS_HOSTNAME, NULL, 0);
		if (ret < 0) {
			goto error;
		}
	} else {
		ctx->sock = zsock_socket(res->ai_family, res->ai_socktype, IPPROTO_TCP);
		if (ctx->sock < 0) {
			goto error;
		}
	}

	/* Connect to the server */
	ret = zsock_connect(ctx->sock, res->ai_addr, res->ai_addrlen);
	if (ret < 0) {
		printf("Connection failed (%d): %s\n", -errno, strerror(errno));
		ctx->sock = -1;
		goto error;
	}

	printf("Connected to %s:%s\n", http_parse_data_st.host, http_parse_data_st.port);
	zsock_freeaddrinfo(res);
	return ctx->sock;

error:
	if (ctx->sock >= 0) {
		zsock_close(ctx->sock);
		ctx->sock = -1;
	}
	zsock_freeaddrinfo(res);
	return -errno;
}

/*
 * @brief Callback for HTTP response processing
 *
 * Processes received HTTP response data in chunks and stores them for firmware update.
 *
 * @param rsp Response structure containing received data
 * @param final_data Flag indicating if this is the final fragment
 * @param user_data User context data (pointer to app_ctx)
 * @return 0 on success, negative error code on failure
 */

static int ota_http_response_cb(struct http_response *rsp, enum http_final_call final_data,
				void *user_data)
{
	struct app_ctx *ctx = (struct app_ctx *)user_data;

	/* Check for HTTP errors */
	if (rsp->http_status_code >= 400) {
		printf("HTTP error: %d %s\n", rsp->http_status_code, rsp->http_status);
		ctx->http_status_code = rsp->http_status_code;
		return -ENODATA;
	}

	if (rsp->http_status_code == 301) {
		printf("HTTP redirect: %d %s\n", rsp->http_status_code, rsp->http_status);
		ctx->http_status_code = rsp->http_status_code;
		return -EPROTO;
	}

	/* Check for empty response */
	if (!rsp->body_frag_len) {
		printf("Warning: Empty response fragment received\n");
		return -ENODATA;
	}

	/* Set total image size from Content-Range header */
	if (rsp->content_range.total > 0) {
		ctx->ota_image_size = rsp->content_range.total;
	}

	if (rsp->body_frag_len > 0) {
		/* Check if we have space in flash_buffer */
		if (ctx->flash_buffer_len + rsp->body_frag_len > sizeof(ctx->flash_buffer)) {
			printf("Buffer overflow would occur! Current: %d, incoming: %d, max: %d\n",
			       ctx->flash_buffer_len, rsp->body_frag_len,
			       sizeof(ctx->flash_buffer));
			return -ENODATA;
		}
		memcpy(ctx->flash_buffer + ctx->flash_buffer_len, rsp->body_frag_start,
		       rsp->body_frag_len);
		ctx->flash_buffer_len += rsp->body_frag_len;
	}

	return 0;
}
/*
 * @brief Download firmware chunk from server
 *
 * @param ctx Pointer to application context
 * @return int 0 on success, negative error code on failure
 */
static int ota_download_firmware_chunk(struct app_ctx *ctx)
{
	int ret = 0;
	char range_header[64];
	const char *headers[2] = { range_header, NULL };
	struct http_request req = {
		.method = HTTP_GET,
		.url = ctx->http_parse_data_st.path,
		.header_fields = headers,
		.host = ctx->http_parse_data_st.host,
		.protocol = "HTTP/1.1",
		.response = ota_http_response_cb,
		.recv_buf = ctx->http_recv_buffer,
		.recv_buf_len = 1024
	};

	/* Reset flash buffer length for new chunk */
	ctx->flash_buffer_len = 0;

	/* Prepare headers */
	snprintf(range_header, sizeof(range_header), "Range: bytes=%d-%d\r\n",
		 ctx->ota_range_start_byte, ctx->ota_range_end_byte);

	/* Send request */
	ret = http_client_req(ctx->sock, &req, 30000, ctx);
	if (ret < 0) {
		printf("HTTP request failed: %d (%s), requested range=%d-%d\n",
		       ctx->http_status_code,
		       (ctx->http_status_code >= 100) ? "HTTP error" : strerror(-ret),
		       ctx->ota_range_start_byte, ctx->ota_range_end_byte);
	}

	if (ctx->http_status_code >= 404) {
		ret = -ENODATA;
	}
	if (ctx->http_status_code == 301) {
		ret = -EPROTO;
	}
	return ret;
}

static bool ota_update_http_range_header(struct app_ctx *ctx)
{
	ctx->ota_range_start_byte = ctx->ota_range_end_byte + 1;

	if (ctx->ota_range_start_byte >= ctx->ota_image_size) {
		return 1;
	}

	ctx->ota_range_end_byte = ctx->ota_range_start_byte + 1023;
	if (ctx->ota_range_end_byte >= ctx->ota_image_size) {
		ctx->ota_range_end_byte = ctx->ota_image_size - 1;
	}
	return 0;
}
/*
 * @brief Process firmware update data packets
 *
 * @param ctx Pointer to application context
 * @return int Status code (0 on success, negative error code on failure)
 */
static int ota_load_firmware(struct app_ctx *ctx)
{
	uint32_t status = 0;
	uint8_t *otaf_image = ctx->flash_buffer;
	uint16_t length = ctx->flash_buffer_len;
	uint32_t ota_calc_image_size = 0;

	__ASSERT(otaf_image && length, "Invalid firmware data parameters\n");

	/* Handle the first packet (header processing) */
	if (ctx->ota_range_start_byte == 0) {
		uint8_t ota_header_size = sizeof(sl_si91x_firmware_header_t);

		status = sl_wifi_get_firmware_size((void *)ctx->flash_buffer, &ota_calc_image_size);
		if (status != SL_STATUS_OK) {
			printf("Unable to fetch firmware size. Status: 0x%x\n", status);
			return -EIO;
		}
		__ASSERT(ctx->ota_image_size == ota_calc_image_size, "Invalid Image");
		printf("Firmware size: %u bytes\n", ctx->ota_image_size);

		/* Process firmware header */
		status = sl_si91x_fwup_start(otaf_image);
		if (status != SL_STATUS_OK) {
			printf("Failed to load firmware header (0x%x)\n", status);
			return -EINVAL;
		}

		/* Load first chunk (after header) */
		status = sl_si91x_fwup_load((otaf_image + ota_header_size),
					    (length - ota_header_size));
		if (status != SL_STATUS_OK) {
			printf("Failed to load first firmware chunk (0x%x)\n", status);
			return -EIO;
		}
	} else {
		/* Handle subsequent packets */
		status = sl_si91x_fwup_load(otaf_image, length);
	}
	printf("Fw load success for requested range=%d-%d\n", ctx->ota_range_start_byte,
	       ctx->ota_range_end_byte);

	/* Check if firmware update is completed */
	if (status == SL_STATUS_SI91X_FW_UPDATE_DONE) {
		return 1;
	} else if (status != SL_STATUS_OK) {
		return -EIO;
	}
	return 0;
}

/*
 * @brief Clean up resources used by the OTA update process
 *
 * @param ctx Pointer to application context structure containing resources to clean up
 */
static void ota_cleanup_resources(struct app_ctx *ctx)
{
	if (ctx->sock >= 0) {
		zsock_close(ctx->sock);
		ctx->sock = -1;
	}
	ctx->flash_buffer_len = 0;
	ctx->http_status_code = 0;
}

/*
 * @brief Handles retry logic for OTA operations
 *
 * @param ctx Pointer to application context
 * @param operation_name Name of the operation being retried for logging
 * @param cleanup_socket Whether to clean up socket resources before retrying
 * @return true if retry should continue, false if max retries exceeded
 */
static bool ota_handle_retry(struct app_ctx *ctx, const char *operation_name, bool cleanup_socket)
{
	/* Clean up socket if needed */
	if (cleanup_socket) {
		ota_cleanup_resources(ctx);
	}
	if (++ctx->retry_count > 2) {
		printf("Maximum retries exceeded, aborting OTA\n");
		ctx->retry_count = 0;
		return false;
	}
	printf("Retrying %s (%d/%d)...\n", operation_name, ctx->retry_count, 2);
	k_sleep(K_MSEC(1000));
	return true;
}

/*
 * @brief Main OTA application state machine
 * @param ctx Pointer to application context
 */
static void ota_application_start(struct app_ctx *ctx)
{
	int ret = 0;
	int firmware_status = 0;
	char *ssid = CONFIG_OTA_WIFI_SSID;
	char *pwd = CONFIG_OTA_WIFI_PSK;
	bool ota_complete = false;

	printf("OTA Application Started\n");
	/* Main state machine loop */
	while (1) {
		switch (ctx->state) {
		case OTA_STATE_SCAN:
			/* Scan for networks and connect */
			ota_wifi_start_scan(ctx);
			ret = ota_wifi_connect(ssid, pwd, ctx);
			if (ret < 0) {
				if (!ota_handle_retry(ctx, "Wi-Fi connection", false)) {
					return;
				}
				break;
			}

			/* Wait for IP configuration */
			ret = ota_wait_for_ip_config(ctx);
			if (ret < 0) {
				return;
			}
			ctx->retry_count = 0;
			ctx->state = OTA_STATE_SERVER_CONNECT;
			break;

		case OTA_STATE_SERVER_CONNECT:
			ret = ota_connect_to_server(ctx);
			if (ret < 0) {
				if (!ota_handle_retry(ctx, "server connection", true)) {
					return;
				}
				break;
			}
			ctx->state = OTA_STATE_DOWNLOAD;
			break;

		case OTA_STATE_DOWNLOAD:
			/* Download firmware chunk */
			ret = ota_download_firmware_chunk(ctx);
			if (ret < 0) {
				if (!ota_handle_retry(ctx, "download", true)) {
					return;
				}
				ctx->state = OTA_STATE_SERVER_CONNECT;
				break;
			}

			firmware_status = ota_load_firmware(ctx);
			if (firmware_status < 0) {
				ctx->state = (ctx->sock < 0) ? OTA_STATE_SERVER_CONNECT
							     : OTA_STATE_DOWNLOAD;
				const char *operation =
					(ctx->sock < 0) ? "server connection" : "download";

				if (!ota_handle_retry(ctx, operation, true)) {
					return;
				}
				break;
			} else if (firmware_status == 1) {
				k_sleep(K_MSEC(3000));
				printf("Firmware update completed. Rebooting...\n");
				sys_reboot();
			} else {
				ota_complete = ota_update_http_range_header(ctx);
			}

			break;
		}
	}
}

int main(void)
{
	static struct app_ctx app_ctx = {
		.events = Z_EVENT_INITIALIZER(app_ctx.events),
		.sock = -1,
		.ota_range_end_byte = 1023,
		.state = OTA_STATE_SCAN,
		.retry_count = 0,
		.ota_image_size = 0
	};

	/* Register WiFi management callback */
	net_mgmt_init_event_callback(&app_ctx.wlan_mgmt_cb, ota_wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS_COMMON);
	net_mgmt_add_event_callback(&app_ctx.wlan_mgmt_cb);

	/* Register IPv4 callback */
	net_mgmt_init_event_callback(&app_ctx.ipv4_mgmt_cb, ota_ipv4_event_handler,
				     NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_ADDR_DEL);
	net_mgmt_add_event_callback(&app_ctx.ipv4_mgmt_cb);

	/* Register IPv6 callback */
	net_mgmt_init_event_callback(&app_ctx.ipv6_mgmt_cb, ota_ipv6_event_handler,
				     NET_EVENT_IPV6_ADDR_ADD | NET_EVENT_IPV6_ADDR_DEL);
	net_mgmt_add_event_callback(&app_ctx.ipv6_mgmt_cb);

	net_mgmt_init_event_callback(&app_ctx.dns_mgmt_cb, ota_dns_event_handler,
				     NET_EVENT_DNS_SERVER_ADD | NET_EVENT_DNS_SERVER_DEL);
	net_mgmt_add_event_callback(&app_ctx.dns_mgmt_cb);

	ota_parse_url(&app_ctx.http_parse_data_st);
	if (!ota_compare_firmware_version(&app_ctx.http_parse_data_st)) {
		printf("The current firmware matches the requested version. No OTA update is "
		       "necessary\n");
		return 0;
	}
	if (IS_ENABLED(CONFIG_NET_DHCPV4)) {
		net_dhcpv4_start(net_if_get_first_wifi());
	}
	ota_application_start(&app_ctx);
	return 0;
}
