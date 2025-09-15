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
#include <errno.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include "firmware_upgradation.h"
#include "sl_wifi.h"

/* Event flags */
#define NET_IPV4_EVENT_READY   BIT(1)
#define NET_IPV6_EVENT_READY   BIT(2)
#define WIFI_SCAN_DONE_EVENT   BIT(3)
#define WIFI_SECURITY_TYPE_SET BIT(4)

struct ota_url {
	bool use_tls;
	char *host;
	char *path;
	char *port;
};

struct app_ctx {
	enum wifi_security_type security_type;
	const char *wifi_ssid;
	const char *wifi_psk;
	struct k_event events;
	struct net_mgmt_event_callback mgmt_cb_ipv4;
	struct net_mgmt_event_callback mgmt_cb_ipv6;
	struct net_mgmt_event_callback mgmt_cb_wlan_scan_result;
	struct net_mgmt_event_callback mgmt_cb_wlan_scan_done;
	struct net_mgmt_event_callback mgmt_cb_wlan_connect;
	struct net_mgmt_event_callback mgmt_cb_wlan_disconnect;
	struct net_mgmt_event_callback mgmt_cb_dns;
	volatile bool ipv4_addr_config_done;
	volatile bool ipv6_addr_config_done;
	volatile bool connected;
	int sock;
	struct ota_url url;
	int http_status_code;
	uint32_t image_size;
	int range_start;

	/* Flash buffer for firmware chunks */
	uint8_t flash_buffer[1024];
	uint32_t flash_buffer_len;

	/* Separate HTTP receive buffer to avoid conflicts */
	uint8_t http_recv_buffer[1024];
};

static char *ota_get_url_field(const char *url, struct http_parser_url parser, int field)
{
	int len = parser.field_data[field].len;
	const char *ptr = url + parser.field_data[field].off;
	char *out;

	__ASSERT(parser.field_set & BIT(field), "Invalid URL");
	out = malloc(len + 1);
	if (out != NULL) {
		memcpy(out, ptr, len);
		out[len] = '\0';
	}
	return out;
}

/*
 * @brief Parse URL into host, path and port components
 */
static int ota_parse_url(struct ota_url *url)
{
	struct http_parser_url parser;
	static char url_str[256];
	const char *schema;
	size_t url_len;
	int ret;

	url_len = strlen(CONFIG_OTA_UPDATE_URL);
	if (url_len >= sizeof(url_str)) {
		printf("URL too long (max %zu bytes)\n", sizeof(url_str) - 1);
		return -EINVAL;
	}
	memcpy(url_str, CONFIG_OTA_UPDATE_URL, url_len + 1);

	http_parser_url_init(&parser);
	ret = http_parser_parse_url(url_str, url_len, 0, &parser);
	__ASSERT(ret == 0, "URL parsing failed");

	url->path = ota_get_url_field(url_str, parser, UF_PATH);
	schema = ota_get_url_field(url_str, parser, UF_SCHEMA);
	url->use_tls = (strcmp(schema, "https") == 0);
	free((void *)schema);

	if ((parser.field_set & BIT(UF_PORT)) == 0) {
		url->port = url->use_tls ? "443" : "80";
	} else {
		url->port = ota_get_url_field(url_str, parser, UF_PORT);
	}
	url->host = ota_get_url_field(url_str, parser, UF_HOST);

	printf("Retrieve %s://%s:%s%s\n", url->use_tls ? "https" : "http", url->host, url->port,
	       url->path);
	return 0;
}

static void ota_ipv4_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface)
{
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, mgmt_cb_ipv4);
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

static void ota_ipv6_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				   struct net_if *iface)
{
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, mgmt_cb_ipv6);
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
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, mgmt_cb_wlan_scan_result);

	if (entry->ssid_length == strlen(ctx->wifi_ssid) &&
	    strncmp(entry->ssid, ctx->wifi_ssid, entry->ssid_length) == 0) {
		ctx->security_type = entry->security;
		k_event_post(&ctx->events, WIFI_SECURITY_TYPE_SET);
	}

	snprintf(mac_string_buf, sizeof(mac_string_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		 entry->mac[0], entry->mac[1], entry->mac[2], entry->mac[3], entry->mac[4],
		 entry->mac[5]);

	printf("%-32s | %-4u (%-6s) | %-4d | %-15s | %-17s | %-8s\n", entry->ssid, entry->channel,
	       wifi_band_txt(entry->band), entry->rssi, wifi_security_txt(entry->security),
	       mac_string_buf, wifi_mfp_txt(entry->mfp));
}

static void ota_handle_wifi_scan_done(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				      struct net_if *iface)
{
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, mgmt_cb_wlan_scan_done);
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printf("Scan request failed (%d)\n", status->status);
	}

	k_event_post(&ctx->events, WIFI_SCAN_DONE_EVENT);
}

static void ota_handle_wifi_connect_result(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
					   struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, mgmt_cb_wlan_connect);

	if (status->status) {
		ctx->connected = false;
		ctx->security_type = WIFI_SECURITY_TYPE_PSK;
	} else {
		printf("Connected to Wi-Fi\n");
		ctx->connected = true;
	}
}

static void ota_handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb,
					      uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *ctx = CONTAINER_OF(cb, struct app_ctx, mgmt_cb_wlan_disconnect);

	printf("Disconnection reason: %d\n", status->disconn_reason);
	ctx->connected = false;
	ctx->security_type = WIFI_SECURITY_TYPE_PSK;
}

static int ota_wifi_start_scan(struct app_ctx *ctx)
{
	struct net_if *iface = net_if_get_first_wifi();
	struct wifi_scan_params params = {};
	int ret;

	printf("%-32s | %-13s | %-4s | %-15s | %-17s | %-8s\n", "SSID", "Chan (Band)", "RSSI",
	       "Security", "BSSID", "MFP");
	ret = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &params, sizeof(params));
	return ret;
}

/*
 * @brief Connect to WiFi network using context configuration
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

	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cnx_params,
		       sizeof(struct wifi_connect_req_params));
	if (ret) {
		printf("Connection request failed: %s\n", strerror(-ret));
	}
	return ret;
}

/*
 * @brief Wait for IP configuration to complete
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
 */
static int ota_connect_to_server(struct app_ctx *ctx)
{
	int peer_verify = TLS_PEER_VERIFY_NONE;
	struct zsock_addrinfo *res;
	int ret;

	ret = zsock_getaddrinfo(ctx->url.host, ctx->url.port, NULL, &res);
	if (ret != 0) {
		printf("Cannot resolve %s:%s: %s\n", ctx->url.host, ctx->url.port,
		       zsock_gai_strerror(ret));
		return -EINVAL;
	}

	if (ctx->url.use_tls) {
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

	printf("Connected to %s:%s\n", ctx->url.host, ctx->url.port);
	zsock_freeaddrinfo(res);
	return 0;

error:
	zsock_close(ctx->sock);
	ctx->sock = -1;
	zsock_freeaddrinfo(res);
	return -errno;
}

/*
 * @brief HTTP response callback - processes firmware chunks
 */
static int ota_http_response_cb(struct http_response *rsp, enum http_final_call final_data,
				void *user_data)
{
	struct app_ctx *ctx = (struct app_ctx *)user_data;

	ctx->http_status_code = rsp->http_status_code;
	ctx->image_size = rsp->content_range.total;

	if (ctx->flash_buffer_len + rsp->body_frag_len > sizeof(ctx->flash_buffer)) {
		return -ENODATA;
	}
	memcpy(ctx->flash_buffer + ctx->flash_buffer_len, rsp->body_frag_start, rsp->body_frag_len);
	ctx->flash_buffer_len += rsp->body_frag_len;

	return 0;
}

/*
 * @brief Download firmware chunk from server
 */
static int ota_download_firmware_chunk(struct app_ctx *ctx)
{
	char range_header[64];
	char *headers[2] = { range_header, NULL };
	int range_end;
	int ret;
	struct http_request req = {
		.method = HTTP_GET,
		.url = ctx->url.path,
		.header_fields = (const char *const *) headers,
		.host = ctx->url.host,
		.protocol = "HTTP/1.1",
		.response = ota_http_response_cb,
		.recv_buf = ctx->http_recv_buffer,
		.recv_buf_len = sizeof(ctx->http_recv_buffer)
	};

	ctx->flash_buffer_len = 0;
	ctx->http_status_code = 0;

	if (ctx->image_size > 0 && ctx->range_start >= (int)ctx->image_size) {
		return -ENODATA;
	}

	range_end = ctx->range_start + sizeof(ctx->flash_buffer) - 1;
	if (ctx->range_start) {
		range_end = MIN(range_end, ctx->image_size);
	}

	/* Prepare headers */
	snprintf(range_header, sizeof(range_header), "Range: bytes=%d-%d\r\n", ctx->range_start,
		 range_end);

	/* Send request */
	ret = http_client_req(ctx->sock, &req, 3000, ctx);
	if (ret < 0) {
		printf("HTTP request failed: %s, requested range=%d-%d\n", strerror(-ret),
		       ctx->range_start, range_end);
		return ret;
	}

	/* Handle HTTP status codes - centralized error management */
	if (ctx->http_status_code >= 300) {
		printf("HTTP error %d, requested range=%d-%d\n", ctx->http_status_code,
		       ctx->range_start, range_end);
		return -EPROTO;
	}
	return 0;
}

/*
 * @brief Process firmware update data packets
 */
static int ota_load_firmware(struct app_ctx *ctx)
{
	uint32_t ota_calc_image_size = 0;
	uint32_t status = 0;
	int buf_offset = 0;

	__ASSERT(ctx->flash_buffer_len > 0, "No firmware data to process");

	if (ctx->range_start == 0) {
		buf_offset = sizeof(sl_si91x_firmware_header_t);
		status = sl_wifi_get_firmware_size(ctx->flash_buffer, &ota_calc_image_size);
		if (status != SL_STATUS_OK) {
			printf("Unable to fetch firmware size. Status: 0x%08x\n", status);
			return -EIO;
		}

		if (ctx->image_size != ota_calc_image_size) {
			printf("Corrupted payload (image size mismatch: %u bytes != %u bytes)\n",
			       ctx->image_size, ota_calc_image_size);
			return -EINVAL;
		}

		printf("Firmware size: %u bytes\n", ctx->image_size);

		status = sl_si91x_fwup_start(ctx->flash_buffer);
		if (status != SL_STATUS_OK) {
			printf("Failed to load firmware header (0x%08x)\n", status);
			return -EINVAL;
		}
	}

	status = sl_si91x_fwup_load(ctx->flash_buffer + buf_offset,
				    ctx->flash_buffer_len - buf_offset);

	printf("Firmware load success for requested range=%d-%d\n", ctx->range_start,
	       ctx->range_start + ctx->flash_buffer_len - 1);

	/* Check if firmware update is completed */
	if (status == SL_STATUS_SI91X_FW_UPDATE_DONE) {
		printf("Firmware update completed. Rebooting...\n");
		sys_reboot();
	}
	if (status != SL_STATUS_OK) {
		return -EIO;
	}
	return 0;
}

/*
 * @brief Main OTA application state machine
 */
static int ota_application_start(struct app_ctx *ctx)
{
	int ret = 0;

	if (!ctx->connected) {
		k_event_clear(&ctx->events, WIFI_SCAN_DONE_EVENT | WIFI_SECURITY_TYPE_SET);
		ota_wifi_start_scan(ctx);

		ret = k_event_wait_safe(&ctx->events, WIFI_SCAN_DONE_EVENT | WIFI_SECURITY_TYPE_SET,
					false, K_SECONDS(10));
		if (ret == 0) {
			return -ETIMEDOUT;
		}

		ret = ota_wifi_connect(ctx);
		if (ret < 0) {
			ctx->security_type = WIFI_SECURITY_TYPE_PSK;
			return ret;
		}
	}

	if ((IS_ENABLED(CONFIG_NET_IPV4) && !ctx->ipv4_addr_config_done) ||
	    (IS_ENABLED(CONFIG_NET_IPV6) && !ctx->ipv6_addr_config_done)) {
		ret = ota_wait_for_ip_config(ctx);
		if (ret < 0) {
			return ret;
		}
	}

	if (ctx->sock < 0) {
		ret = ota_connect_to_server(ctx);
		if (ret < 0) {
			return ret;
		}
	}

	ret = ota_download_firmware_chunk(ctx);
	if (ret < 0) {
		goto out_close;
	}

	ret = ota_load_firmware(ctx);
	if (ret < 0) {
		goto out_reset;
	}
	ctx->range_start += sizeof(ctx->flash_buffer);
	return 0;

out_reset:
	ctx->range_start = 0;
out_close:
	zsock_close(ctx->sock);
	ctx->sock = -1;
	return ret;
}

int main(void)
{
	static struct app_ctx app_ctx = {
		.events = Z_EVENT_INITIALIZER(app_ctx.events),
		.sock = -1,
		.wifi_ssid = CONFIG_OTA_WIFI_SSID,
		.wifi_psk = CONFIG_OTA_WIFI_PSK,
		.security_type = WIFI_SECURITY_TYPE_PSK,
	};
	int retry_count = 0;
	int ret = 0;

	/* Register WiFi management callbacks */
	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_wlan_scan_result, ota_handle_wifi_scan_result,
				     NET_EVENT_WIFI_SCAN_RESULT);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_wlan_scan_result);

	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_wlan_scan_done, ota_handle_wifi_scan_done,
				     NET_EVENT_WIFI_SCAN_DONE);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_wlan_scan_done);

	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_wlan_connect, ota_handle_wifi_connect_result,
				     NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_wlan_connect);

	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_wlan_disconnect,
				     ota_handle_wifi_disconnect_result,
				     NET_EVENT_WIFI_DISCONNECT_RESULT);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_wlan_disconnect);

	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_ipv4, ota_ipv4_event_handler,
				     NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_ADDR_DEL);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_ipv4);

	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_ipv6, ota_ipv6_event_handler,
				     NET_EVENT_IPV6_ADDR_ADD | NET_EVENT_IPV6_ADDR_DEL);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_ipv6);

	net_mgmt_init_event_callback(&app_ctx.mgmt_cb_dns, ota_dns_event_handler,
				     NET_EVENT_DNS_SERVER_ADD | NET_EVENT_DNS_SERVER_DEL);
	net_mgmt_add_event_callback(&app_ctx.mgmt_cb_dns);

	ota_parse_url(&app_ctx.url);
	if (IS_ENABLED(CONFIG_NET_DHCPV4)) {
		net_dhcpv4_start(net_if_get_first_wifi());
	}
	printf("OTA Application Started\n");
	while (retry_count < 3) {
		ret = ota_application_start(&app_ctx);
		if (ret < 0) {
			retry_count++;
			k_sleep(K_MSEC(1000));
		}
	}
	printf("Maximum retries exceeded, aborting OTA\n");
	return 0;
}
