/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include "firmware_upgradation.h"
#include "sl_wifi.h"

/* Event masks */
#define WIFI_SHELL_MGMT_EVENTS_COMMON                                                              \
	(NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE | NET_EVENT_WIFI_CONNECT_RESULT |   \
	 NET_EVENT_WIFI_DISCONNECT_RESULT)

/* Event flags */
#define NET_IPV4_EVENT_READY BIT(1)
#define NET_IPV6_EVENT_READY BIT(2)

/* OTA update state machine states */
enum ota_state {
	OTA_STATE_SCAN,           /**< Scan for WiFi networks */
	OTA_STATE_SERVER_CONNECT, /**< Connect to OTA server */
	OTA_STATE_DOWNLOAD        /**< Download and process firmware image */
};

struct http_parse_data {
	bool is_tls_enabled;
	char *host;
	char *path;
	char *port;
};

struct app_ctx {
	uint16_t scan_result_count;
	enum wifi_security_type security_type;
	const char *wifi_ssid;
	const char *wifi_psk;
	struct k_event events;
	struct net_mgmt_event_callback ipv4_mgmt_cb;
	struct net_mgmt_event_callback ipv6_mgmt_cb;
	struct net_mgmt_event_callback wlan_mgmt_cb_scan_result;
	struct net_mgmt_event_callback wlan_mgmt_cb_scan_done;
	struct net_mgmt_event_callback wlan_mgmt_cb_connect;
	struct net_mgmt_event_callback wlan_mgmt_cb_disconnect;
	struct net_mgmt_event_callback dns_mgmt_cb;
	volatile enum ota_state state;
	volatile bool ipv4_addr_config_done;
	volatile bool ipv6_addr_config_done;
	volatile bool disconnected;
	int sock;
	struct http_parse_data http_parse_info;
	int http_status_code;
	uint32_t image_size;
	int range_start;
	int range_end;

	/* Flash buffer for firmware chunks */
	uint8_t flash_buffer[1024];
	uint32_t flash_buffer_len;

	/* Separate HTTP receive buffer to avoid conflicts */
	uint8_t http_recv_buffer[1024];

	uint8_t retry_count;
};

static char *ota_get_url_field(const char *url, struct http_parser_url parser, int field)
{
	int len = parser.field_data[field].len;
	const char *ptr = url + parser.field_data[field].off;
	char *out;

	__ASSERT(parser.field_set & BIT(field), "Invalid URL");
	out = strndup(ptr, len);
	return out;
}

/*
 * @brief Parses URL into host, path and port components
 * @param http_parse_info Pointer to structure to store the parsed URL components
 * @return 0 on success, negative error code on failure
 */
static int ota_parse_url(struct http_parse_data *http_parse_info)
{
	char *full_url = CONFIG_OTA_UPDATE_URL;
	struct http_parser_url parser;
	int ret = 0;

	http_parser_url_init(&parser);
	ret = http_parser_parse_url(full_url, strlen(full_url), 0, &parser);
	__ASSERT(ret == 0, "URL parsing failed");

	/* Determine if TLS is enabled based on schema */
	char *schema = ota_get_url_field(full_url, parser, UF_SCHEMA);
	http_parse_info->is_tls_enabled = (strcmp(schema, "https") == 0);
	free(schema);

	http_parse_info->host = ota_get_url_field(full_url, parser, UF_HOST);
	http_parse_info->path = ota_get_url_field(full_url, parser, UF_PATH);
	http_parse_info->port = ota_get_url_field(full_url, parser, UF_PORT);

	if ((parser.field_set & BIT(UF_PORT)) == 0) {
		http_parse_info->port = http_parse_info->is_tls_enabled ? "443" : "80";
	} else {
		http_parse_info->port = ota_get_url_field(full_url, parser, UF_PORT);
	}

	printf("Retrieve %s://%s:%s%s\n", http_parse_info->is_tls_enabled ? "https" : "http",
	       http_parse_info->host, http_parse_info->port, http_parse_info->path);
	return 0;
}

static void ota_cleanup_resources(struct app_ctx *ctx)
{
	zsock_close(ctx->sock);
	ctx->sock = -1;
	ctx->flash_buffer_len = 0;
	ctx->http_status_code = 0;
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
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, ipv4_mgmt_cb);
	char addr[INET_ADDRSTRLEN];

	net_addr_ntop(AF_INET, cb->info, addr, sizeof(addr));
	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		printf("Added IPv4 Address: %s\n", addr);
		ctx->ipv4_addr_config_done = true;
		k_event_post(&ctx->events, NET_IPV4_EVENT_READY);
	} else {
		ctx->ipv4_addr_config_done = false;
		printf("Removed IPv4 Address: %s\n", addr);
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
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, ipv6_mgmt_cb);
	char addr[INET6_ADDRSTRLEN];

	net_addr_ntop(AF_INET6, cb->info, addr, sizeof(addr));
	if (mgmt_event == NET_EVENT_IPV6_ADDR_ADD) {
		printf("Added IPv6 Address: %s\n", addr);
		k_event_post(&ctx->events, NET_IPV6_EVENT_READY);
		ctx->ipv6_addr_config_done = true;
	} else {
		printf("Removed IPv6 Address: %s\n", addr);
		ctx->ipv6_addr_config_done = false;
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
		op = "Removed";
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

static void ota_handle_wifi_scan_result(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
					struct net_if *iface)
{
	const struct wifi_scan_result *entry = (const struct wifi_scan_result *)cb->info;
	uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];
	uint8_t ssid_print[WIFI_SSID_MAX_LEN + 1];
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb_scan_result);

	if (strncmp(entry->ssid, ctx->wifi_ssid, entry->ssid_length) == 0) {
		ctx->security_type = entry->security;
	}

	strncpy(ssid_print, entry->ssid, sizeof(ssid_print) - 1);

	snprintf(mac_string_buf, sizeof(mac_string_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		 entry->mac[0], entry->mac[1], entry->mac[2], entry->mac[3], entry->mac[4],
		 entry->mac[5]);

	printf("%-32s | %-4u (%-6s) | %-4d | %-15s | %-17s | %-8s\n", ssid_print, entry->channel,
	       wifi_band_txt(entry->band), entry->rssi, wifi_security_txt(entry->security),
	       mac_string_buf, wifi_mfp_txt(entry->mfp));
}

static void ota_handle_wifi_scan_done(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				      struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printf("Scan request failed (%d)\n", status->status);
	}
}

static void ota_handle_wifi_connect_result(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
					   struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb_connect);

	if (status->status) {
		printf("Connection request failed\n");
	} else {
		printf("Connected to Wi-Fi\n");
	}
	ctx->disconnected = false;
}

static void ota_handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb,
					      uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb_disconnect);

	printf("Disconnection reason: %d\n", status->disconn_reason);
	ctx->disconnected = true;
}

static int ota_wifi_start_scan(struct app_ctx *ctx)
{
	struct net_if *iface = net_if_get_first_wifi();
	struct wifi_scan_params params = {};
	int ret;

	printf("%-4s | %-32s %-5s | %-13s | %-4s | %-15s | %-17s | %-8s\n", "Num", "SSID", "(len)",
	       "Chan (Band)", "RSSI", "Security", "BSSID", "MFP");
	ret = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &params, sizeof(params));
	return ret;
}

/*
 * @brief Connect to WiFi network
 *
 * @param ssid Network SSID
 * @param pwd Network password
 * @param ctx App context pointer
 * @return int 0 on success, negative error code on failure
 */
static int ota_wifi_connect(struct app_ctx *ctx)
{
	struct wifi_connect_req_params cnx_params = {
		.channel = WIFI_CHANNEL_ANY,
		.band = 0,
		.security = ctx->security_type,
		.psk_length = strlen(ctx->wifi_psk),
		.psk = (uint8_t *)ctx->wifi_psk,
		.ssid_length = strlen(ctx->wifi_ssid),
		.ssid = (uint8_t *)ctx->wifi_ssid
	};
	struct net_if *iface = net_if_get_first_wifi();
	int ret;

	printf("Connecting to network: %s\n", ctx->wifi_ssid);
	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cnx_params,
		       sizeof(struct wifi_connect_req_params));
	if (ret) {
		printf("Connection request failed: %s\n", strerror(-ret));
	}
	return ret;
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
	int peer_verify = TLS_PEER_VERIFY_NONE;
	struct zsock_addrinfo *res;
	int ret;

	ret = zsock_getaddrinfo(ctx->http_parse_info.host, ctx->http_parse_info.port, NULL, &res);
	if (ret != 0) {
		printf("Cannot resolve %s:%s: %s\n", ctx->http_parse_info.host,
		       ctx->http_parse_info.port, zsock_gai_strerror(ret));
		return ret;
	}

	/* Check if TLS is needed */
	if (ctx->http_parse_info.is_tls_enabled) {
		ctx->sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TLS_1_2);
		if (ctx->sock < 0) {
			goto error;
		}
		ret = zsock_setsockopt(ctx->sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify,
				       sizeof(peer_verify));
		if (ret < 0) {
			goto error;
		}
	} else {
		/* Use regular TCP for HTTP */
		ctx->sock = zsock_socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (ctx->sock < 0) {
			goto error;
		}
	}

	/* Connect to the server */
	ret = zsock_connect(ctx->sock, res->ai_addr, res->ai_addrlen);
	if (ret < 0) {
		printf("Connection failed: %s\n", strerror(errno));
		goto error;
	}

	printf("Connected to %s:%s\n", ctx->http_parse_info.host, ctx->http_parse_info.port);
	zsock_freeaddrinfo(res);
	return 0;

error:
	zsock_close(ctx->sock);
	ctx->sock = -1;
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

	ctx->http_status_code = rsp->http_status_code;
	ctx->image_size = rsp->content_range.total;

	if (rsp->body_frag_len > 0) {
		/* Check if we have space in flash_buffer */
		if (ctx->flash_buffer_len + rsp->body_frag_len > sizeof(ctx->flash_buffer)) {
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
	char range_header[64];
	const char *headers[2] = { range_header, NULL };
	int ret = 0;
	struct http_request req = {
		.method = HTTP_GET,
		.url = ctx->http_parse_info.path,
		.header_fields = headers,
		.host = ctx->http_parse_info.host,
		.protocol = "HTTP/1.1",
		.response = ota_http_response_cb,
		.recv_buf = ctx->http_recv_buffer,
		.recv_buf_len = sizeof(ctx->http_recv_buffer)
	};

	/* Reset flash buffer length for new chunk */
	ctx->flash_buffer_len = 0;

	/* Prepare headers */
	snprintf(range_header, sizeof(range_header), "Range: bytes=%d-%d\r\n", ctx->range_start,
		 ctx->range_end);

	/* Send request */
	ret = http_client_req(ctx->sock, &req, 3000, ctx);
	if (ret < 0) {
		printf("HTTP request failed: %s, requested range=%d-%d\n", strerror(-ret),
		       ctx->range_start, ctx->range_end);
		return ret;
	}

	/* Handle HTTP status codes - centralized error management */
	if (ctx->http_status_code >= 300) {
		printf("HTTP error %d, requested range=%d-%d\n", ctx->http_status_code,
		       ctx->range_start, ctx->range_end);
		return -EPROTO;
	}
	return ret;
}

static int ota_update_http_range_header(struct app_ctx *ctx)
{
	ctx->range_start += sizeof(ctx->flash_buffer);

	if (ctx->range_start >= ctx->image_size) {
		return -ENODATA;
	}

	ctx->range_end = ctx->range_start + sizeof(ctx->flash_buffer) - 1;
	if (ctx->range_end >= ctx->image_size) {
		ctx->range_end = ctx->image_size - 1;
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
	uint32_t ota_calc_image_size = 0;
	uint32_t status = 0;
	int buf_offset = 0;

	__ASSERT(ctx->flash_buffer_len > 0, "No firmware data to process");

	/* Handle the first packet (header processing) */
	if (ctx->range_start == 0) {
		buf_offset = sizeof(sl_si91x_firmware_header_t);
		status = sl_wifi_get_firmware_size((void *)ctx->flash_buffer, &ota_calc_image_size);
		if (status != SL_STATUS_OK) {
			printf("Unable to fetch firmware size. Status: 0x%x\n", status);
			return -EIO;
		}

		/* Check if downloaded image size matches the calculated size */
		if (ctx->image_size != ota_calc_image_size) {
			printf("Image size mismatch - expected: %u, calculated: %u (file may be "
			       "corrupted)\n",
			       ctx->image_size, ota_calc_image_size);
			return -EINVAL;
		}

		printf("Firmware size: %u bytes\n", ctx->image_size);

		/* Process firmware header */
		status = sl_si91x_fwup_start(ctx->flash_buffer);
		if (status != SL_STATUS_OK) {
			printf("Failed to load firmware header (0x%x)\n", status);
			return -EINVAL;
		}
	}

	status = sl_si91x_fwup_load(ctx->flash_buffer + buf_offset,
				    ctx->flash_buffer_len - buf_offset);
	if (status != SL_STATUS_OK) {
		return -EIO;
	}

	printf("Firmware load success for requested range=%d-%d\n", ctx->range_start,
	       ctx->range_end);

	/* Check if firmware update is completed */
	if (status == SL_STATUS_SI91X_FW_UPDATE_DONE) {
		return 1;
	} else if (status != SL_STATUS_OK) {
		return -EIO;
	}
	return 0;
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
	const char *operation;
	int ret = 0;

	printf("OTA Application Started\n");
	/* Main state machine loop */
	while (ctx->retry_count < 3) {
		switch (ctx->state) {
		case OTA_STATE_SCAN:
			/* Scan for networks and connect */
			ota_wifi_start_scan(ctx);
			ret = ota_wifi_connect(ctx);
			if (ret) {
				ota_handle_retry(ctx, "Wi-Fi connection", false);
				continue;
			}

			/* Wait for IP configuration */
			ret = ota_wait_for_ip_config(ctx);
			if (ret < 0) {
				ota_handle_retry(ctx, "IP configuration", false);
				continue;
			}

			ctx->state = OTA_STATE_SERVER_CONNECT;
			break;

		case OTA_STATE_SERVER_CONNECT:
			ret = ota_connect_to_server(ctx);
			if (ret < 0) {
				ota_handle_retry(ctx, "server connection", true);
				continue;
			}
			ctx->state = OTA_STATE_DOWNLOAD;
			break;

		case OTA_STATE_DOWNLOAD:
			if (!ctx->ipv4_addr_config_done || !ctx->ipv6_addr_config_done ||
			    ctx->disconnected) {
				ota_handle_retry(ctx, "network connection", true);
				ctx->state = OTA_STATE_SCAN;
				continue;
			}
			/* Download firmware chunk */
			ret = ota_download_firmware_chunk(ctx);
			if (ret < 0) {
				ota_handle_retry(ctx, "download", true);
				ctx->state = OTA_STATE_SERVER_CONNECT;
				continue;
			}

			ret = ota_load_firmware(ctx);
			if (ret < 0) {
				if ((ret == -EINVAL) || (ctx->sock < 0)) {
					ctx->state = OTA_STATE_SERVER_CONNECT;
					operation = "download";
					ctx->range_start = 0;
					ctx->range_end = 1023;
				}

				if (!ota_handle_retry(ctx, operation, true)) {
					continue;
				}
				break;
			} else if (ret == 1) {
				printf("Firmware update completed. Rebooting...\n");
				sys_reboot();
			} else {
				ret = ota_update_http_range_header(ctx);
				if (ret < 0) {
					ctx->state = OTA_STATE_SERVER_CONNECT;
					ctx->range_start = 0;
					ctx->range_end = 1023;
					break;
				}
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
		.range_start = 0,
		.range_end = 1023,
		.state = OTA_STATE_SCAN,
		.wifi_ssid = CONFIG_OTA_WIFI_SSID,
		.wifi_psk = CONFIG_OTA_WIFI_PSK,
		.security_type = WIFI_SECURITY_TYPE_PSK,
		.disconnected = true,
		.retry_count = 0
	};

	/* Register WiFi management callbacks */
	net_mgmt_init_event_callback(&app_ctx.wlan_mgmt_cb_scan_result, ota_handle_wifi_scan_result,
				     NET_EVENT_WIFI_SCAN_RESULT);
	net_mgmt_add_event_callback(&app_ctx.wlan_mgmt_cb_scan_result);

	net_mgmt_init_event_callback(&app_ctx.wlan_mgmt_cb_scan_done, ota_handle_wifi_scan_done,
				     NET_EVENT_WIFI_SCAN_DONE);
	net_mgmt_add_event_callback(&app_ctx.wlan_mgmt_cb_scan_done);

	net_mgmt_init_event_callback(&app_ctx.wlan_mgmt_cb_connect, ota_handle_wifi_connect_result,
				     NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&app_ctx.wlan_mgmt_cb_connect);

	net_mgmt_init_event_callback(&app_ctx.wlan_mgmt_cb_disconnect,
				     ota_handle_wifi_disconnect_result,
				     NET_EVENT_WIFI_DISCONNECT_RESULT);
	net_mgmt_add_event_callback(&app_ctx.wlan_mgmt_cb_disconnect);

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

	ota_parse_url(&app_ctx.http_parse_info);
	if (IS_ENABLED(CONFIG_NET_DHCPV4)) {
		net_dhcpv4_start(net_if_get_first_wifi());
	}
	ota_application_start(&app_ctx);
	return 0;
}
