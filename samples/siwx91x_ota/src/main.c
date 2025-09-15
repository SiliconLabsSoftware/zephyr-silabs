/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Running this application under net offload mode */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_http_client_sample, LOG_LEVEL_DBG);

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <zephyr/linker/sections.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/dhcpv6.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/portability/cmsis_os2.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>
#include <zephyr/types.h>
#include "firmware_upgradation.h"
#include "sl_additional_status.h"
#include "sl_si91x_types.h"
#include "sl_utility.h"
#include "sl_wifi_callback_framework.h"
#include "sl_wifi.h"

/* Event masks */
#define WIFI_SHELL_MGMT_EVENTS_COMMON                                                              \
	(NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE | NET_EVENT_WIFI_CONNECT_RESULT |   \
	 NET_EVENT_WIFI_DISCONNECT_RESULT)

/* Network configuration */
#define CMD_WAIT_TIME_MS    180000 /**< Command timeout in milliseconds */
#define MAX_RECV_BUF_LEN    1460   /**< Maximum receive buffer length */
#define HTTP_MSG_Q_MAX_SIZE 16     /**< HTTP message queue size */
#define RECV_BUFFER_SIZE    1024   /**< Network receive buffer size */

/* Firmware update configuration */
#define CHUNK_SIZE                   (10 * 1024) /**< Download chunk size */
#define FW_CHUNK_SIZE                1024        /**< Firmware write chunk size */
#define FW_CHUNK_DOWNLOAD_TIMEOUT_MS 30000       /**< Firmware chunk download timeout */
#define HTTP_RESP_TIMEOUT_MS         30000       /**< HTTP response timeout */

/* Retry configuration */
#define MAX_RETRIES 3 /**< Maximum retry attempts */

/* TLS configuration */
#define TLS_TAG_CA_CERTIFICATE 1 /**< CA certificate security tag */

/* OTA update state machine states */
enum ota_state {
	OTA_STATE_SCAN,           /**< Wi-Fi scanning */
	OTA_STATE_CONNECT,        /**< Connect to Wi-Fi network */
	OTA_STATE_IP_CONFIG,      /**< Get IP configuration */
	OTA_STATE_SERVER_CONNECT, /**< Connect to OTA server */
	OTA_STATE_DOWNLOAD,       /**< Download firmware image */
	OTA_STATE_PROCESS         /**< Process downloaded firmware */
};

/* Message for HTTP data */
typedef struct {
	uint32_t length;
	uint8_t buffer[RECV_BUFFER_SIZE];
} msg_t;

struct http_parse_data {
	char schema[6];
	char host[100];
	char path[100];
	char port[6];
	bool is_tls_enabled;
};

struct app_ctx {
	struct net_if *iface;
	struct k_sem wlan_sem;
	struct k_sem dhcp_sem;
	struct k_sem ota_sem;
	struct net_mgmt_event_callback dhcp_mgmt_cb;
	struct net_mgmt_event_callback wlan_mgmt_cb;
	struct net_mgmt_event_callback l4_cb;
	volatile enum ota_state state;
	volatile bool ipv6_addr_config_done;
	int sock;
	struct http_parse_data http_parse_data_st;
	uint8_t http_recv_buf[MAX_RECV_BUF_LEN];
	uint32_t ota_image_size;
	int ota_range_start_byte;
	int ota_range_end_byte;
	msg_t msg_c;
	bool http_response_error;
	char http_data_q_buffer[HTTP_MSG_Q_MAX_SIZE * sizeof(msg_t)];
	struct k_msgq http_data_q;
};

extern unsigned char ca_cert_der[];
extern unsigned int ca_cert_der_len;

static void ota_application_start(struct app_ctx *app_ctx_st);
static void start_dhcpv4_client(struct net_if *iface, void *user_data);
static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				    struct net_if *iface);
static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb);
static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb);
static void handle_wifi_scan_done(struct net_mgmt_event_callback *cb);
static void handle_wifi_scan_result(struct net_mgmt_event_callback *cb);
int ota_load_firmware(struct app_ctx *app_ctx_st);
static void dhcp_callback_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				  struct net_if *iface);

/*
 * @brief Handles IPv6 connectivity events
 *
 * Processes Layer 4 connectivity events for IPv6, displaying network information
 * when an IPv6 connection is established.
 *
 * @param cb Pointer to the event callback structure
 * @param event The network event to handle
 * @param iface Network interface that generated the event
 */
static void l4_event_handler(struct net_mgmt_event_callback *cb, uint64_t event,
			     struct net_if *iface)
{
	int i = 0;
	char ipv6_address[NET_IPV6_ADDR_LEN];
	char link_local[NET_IPV6_ADDR_LEN];
	struct app_ctx *app_ctx_st = CONTAINER_OF(cb, struct app_ctx, l4_cb);

	if (event == NET_EVENT_L4_IPV6_CONNECTED) {
		printf("Network connectivity established and IPv6 address assigned\n");
		for (i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {

			net_addr_ntop(AF_INET6, &iface->config.ip.ipv6->unicast[i].address.in6_addr,
				      link_local, sizeof(link_local));
			if (!strncmp(link_local, "fe80", 4)) {
				printf("IPv6 Link local Address:%s\n", link_local);
			} else {
				memcpy(ipv6_address, link_local, sizeof(link_local));
				printf("IPv6 global address:%s\n", ipv6_address);
			}
		}
		app_ctx_st->ipv6_addr_config_done = true;
	}
}

/*
 * @brief Starts DHCPv4 client on the given network interface
 *
 * @param iface Network interface where DHCP client should be started
 * @param user_data User data (unused)
 */
static void start_dhcpv4_client(struct net_if *iface, void *user_data)
{
	ARG_UNUSED(user_data);

	printf("Start on %s: index=%d\n", net_if_get_device(iface)->name,
	       net_if_get_by_iface(iface));
	net_dhcpv4_start(iface);
}

/*
 * @brief Handles DHCPv4 address assignment events
 *
 * Processes events when IPv4 addresses are assigned via DHCP, printing
 * the assigned network configuration.
 *
 * @param cb Pointer to the event callback structure
 * @param mgmt_event The network management event being handled
 * @param iface Network interface that generated the event
 */
static void dhcp_callback_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				  struct net_if *iface)
{
	int i = 0;
	char buf[NET_IPV4_ADDR_LEN];
	struct app_ctx *app_ctx_st = CONTAINER_OF(cb, struct app_ctx, dhcp_mgmt_cb);

	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
			if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP) {
				continue;
			}

			printf("Address[%d]: %s", net_if_get_by_iface(iface),
			       net_addr_ntop(
				       AF_INET,
				       &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr, buf,
				       sizeof(buf)));
			printf("    Subnet[%d]: %s", net_if_get_by_iface(iface),
			       net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[i].netmask,
					     buf, sizeof(buf)));
			printf("    Router[%d]: %s", net_if_get_by_iface(iface),
			       net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, buf,
					     sizeof(buf)));
			printf("    Lease time[%d]: %u seconds\n", net_if_get_by_iface(iface),
			       iface->config.dhcpv4.lease_time);

			k_sem_give(&app_ctx_st->dhcp_sem);
		}
	}
}

/*
 * @brief Callback for HTTP response processing
 *
 * Processes received HTTP response data in chunks and queues them for firmware update.
 * Handles error conditions and manages data fragmentation.
 *
 * @param rsp Response structure containing received data
 * @param final_data Flag indicating if this is the final fragment
 * @param user_data User context data (pointer to app_ctx)
 * @return 0 on success, negative error code on failure
 */
static int ota_http_response_cb(struct http_response *rsp, enum http_final_call final_data,
				void *user_data)
{
	struct app_ctx *app_ctx_st = (struct app_ctx *)user_data;
	size_t offset = 0;
	static uint8_t staging_buf[FW_CHUNK_SIZE];
	static size_t staging_len;
	static msg_t msg_p;

	app_ctx_st->http_response_error = false;

	/* Check for HTTP errors */
	if (rsp->http_status_code >= 400) {
		printf("HTTP error: %d %s\n", rsp->http_status_code, rsp->http_status);
		app_ctx_st->http_response_error = true;
		return -ENODATA;
	}

	/* Check for empty response */
	if (!rsp->body_frag_len) {
		printf("Warning: Empty response fragment received\n");
		if (final_data) {
			app_ctx_st->http_response_error = true;
		}
		return -ENODATA;
	}

	if (final_data == HTTP_DATA_MORE) {
		printf("Partial data received (%zd bytes)\n", rsp->body_frag_len);
	} else if (final_data == HTTP_DATA_FINAL) {
		printf("All data received (%zd bytes)\n", rsp->body_frag_len);
	}

	/* Copy received data into staging buffer and push 1024-byte chunks */
	while (offset < rsp->body_frag_len) {
		size_t space_left = FW_CHUNK_SIZE - staging_len;
		size_t to_copy = (rsp->body_frag_len - offset < space_left)
					 ? (rsp->body_frag_len - offset)
					 : space_left;

		memcpy(staging_buf + staging_len, rsp->body_frag_start + offset, to_copy);
		staging_len += to_copy;
		offset += to_copy;

		/* If we have a full chunk, push to queue */
		if (staging_len == FW_CHUNK_SIZE) {
			msg_p.length = FW_CHUNK_SIZE;
			memcpy(msg_p.buffer, staging_buf, FW_CHUNK_SIZE);
			if (k_msgq_put(&app_ctx_st->http_data_q, &msg_p, K_NO_WAIT)) {
				printf("Unable to queue the data\n");
				app_ctx_st->http_response_error = true;
				return -errno;
			}
			staging_len = 0; /* Reset for next chunk */
		}
	}
	/* If this is the final data and there are leftover bytes, push them as the last chunk */
	if (final_data && staging_len > 0) {
		msg_p.length = staging_len;
		memcpy(msg_p.buffer, staging_buf, staging_len);
		if (k_msgq_put(&app_ctx_st->http_data_q, &msg_p, K_NO_WAIT)) {
			printf("Unable to queue the data\n");
			app_ctx_st->http_response_error = true;
			return -errno;
		}
		staging_len = 0;
	}
	if (final_data || app_ctx_st->http_response_error) {
		k_sem_give(&app_ctx_st->ota_sem);
	}
	return 0;
}

/*
 * @brief Initialize WiFi scanning
 * @param app_ctx_st Pointer to application context structure
 * @return int 0 on success, negative error code on failure
 */
static int wifi_start_scan(struct app_ctx *app_ctx_st)
{
	struct wifi_scan_params params = {};

	params.dwell_time_active = 99;
	printf("Starting WiFi scan...\n");
	if (net_mgmt(NET_REQUEST_WIFI_SCAN, app_ctx_st->iface, &params, sizeof(params))) {
		printf("Scan request failed\n");
		return -errno;
	}
	printf("Scan requested\n");
	if (k_sem_take(&app_ctx_st->wlan_sem, K_MSEC(CMD_WAIT_TIME_MS)) != 0) {
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
 * @param security Security type
 * @return int 0 on success, negative error code on failure
 */
static int wifi_connect(const char *ssid, const char *pwd, uint8_t security,
			struct app_ctx *app_ctx_st)
{
	int ret;
	struct wifi_connect_req_params cnx_params = {0};

	if (!ssid || !pwd) {
		printf("Invalid connection parameters\n");
		return -EINVAL;
	}
	printf("Connecting to network: %s\n", ssid);

	/* Fill connection parameters */
	cnx_params.channel = WIFI_CHANNEL_ANY;
	cnx_params.band = 0;
	cnx_params.security = security;
	cnx_params.psk_length = strlen(pwd);
	cnx_params.psk = (uint8_t *)pwd;
	cnx_params.ssid_length = strlen(ssid);
	cnx_params.ssid = (uint8_t *)ssid;

	/* Request connection */
	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, app_ctx_st->iface, &cnx_params,
		       sizeof(struct wifi_connect_req_params));
	if (ret) {
		printf("Connection request failed with error: %d\n", ret);
		return -errno;
	}
	printf("Connection requested\n");
	if (k_sem_take(&app_ctx_st->wlan_sem, K_MSEC(CMD_WAIT_TIME_MS)) != 0) {
		printf("WiFi connect failed or timed out\n");
		return -errno;
	}
	return 0;
}

/*
 * @brief Configure IP networking
 * @param app_ctx_st Pointer to application context structure
 * @return int 0 on success, negative error code on failure
 */
static int configure_ip(struct app_ctx *app_ctx_st)
{
	printf("Configuring IP networking...\n");

#if (CONFIG_OTA_IP_PROTOCOL_SELECTION == 0)
	net_if_foreach(start_dhcpv4_client, NULL);
	if (k_sem_take(&app_ctx_st->dhcp_sem, K_MSEC(CMD_WAIT_TIME_MS)) != 0) {
		printf("IP configuration failed or timed out\n");
		return -errno;
	}
#endif
	return 0;
}

/*
 * @brief Parses URL into host, path and port components
 *
 * Extracts the different components of the OTA update URL to prepare
 * for connecting to the server.
 *
 * @param http_parse_data_st Pointer to structure to store the parsed URL components
 * @return 0 on success, negative error code on failure
 */
int ota_parse_url(struct http_parse_data *http_parse_data_st)
{
	struct http_parser_url parser;
	char *full_url = CONFIG_OTA_UPDATE_URL;
	size_t data_len;
	int ret = 0;

	http_parser_url_init(&parser);
	http_parser_parse_url(full_url, strlen(full_url), 0, &parser);
	ret = 1;
	__ASSERT(ret != 0, "URL parsing failed");

	/* Get the schema, host, port and path info from the parsed URL */
	if (parser.field_set & (1 << UF_SCHEMA)) {
		data_len = parser.field_data[UF_SCHEMA].len;
		memcpy(http_parse_data_st->schema, &full_url[parser.field_data[UF_SCHEMA].off],
		       data_len);
		http_parse_data_st->schema[data_len] = '\0';
		http_parse_data_st->is_tls_enabled =
			(strcmp(http_parse_data_st->schema, "https") == 0) ? 1 : 0;
		printf("Schema: %s\n", http_parse_data_st->schema);
	} else {
		__ASSERT(false, "Schema field missing in URL");
	}
	if (parser.field_set & (1 << UF_HOST)) {
		data_len = parser.field_data[UF_HOST].len;
		memcpy(http_parse_data_st->host, &full_url[parser.field_data[UF_HOST].off],
		       data_len);
		http_parse_data_st->host[data_len] = '\0';
		printf("Host: %s\n", http_parse_data_st->host);
	} else {
		__ASSERT(false, "Host field missing in URL");
	}

	if (parser.field_set & (1 << UF_PATH)) {
		data_len = parser.field_data[UF_PATH].len;
		memcpy(http_parse_data_st->path, &full_url[parser.field_data[UF_PATH].off],
		       data_len);
		http_parse_data_st->path[data_len] = '\0';
		printf("Path: %s\n", http_parse_data_st->path);
	} else {
		__ASSERT(false, "Path field missing in URL");
	}

	if (parser.field_set & (1 << UF_PORT)) {
		data_len = parser.field_data[UF_PORT].len;
		memcpy(http_parse_data_st->port, &full_url[parser.field_data[UF_PORT].off],
		       data_len);
		http_parse_data_st->port[data_len] = '\0';
		printf("Port: %s\n", http_parse_data_st->port);
	} else {
		strcpy(http_parse_data_st->port, http_parse_data_st->is_tls_enabled ? "443" : "80");
		printf("Port: %s\n", http_parse_data_st->port);
	}
	return 0;
}

/*
 * @brief Connect to OTA server
 *
 * @param app_ctx_st Pointer to application context structure
 * @return int 0 on success, negative error code on failure
 */
static int connect_to_ota_server(struct app_ctx *app_ctx_st)
{
	int ret;
	struct zsock_addrinfo *res;
	int *sock_ptr = &app_ctx_st->sock;
	struct http_parse_data http_parse_data_st = app_ctx_st->http_parse_data_st;

	ret = zsock_getaddrinfo(http_parse_data_st.host, http_parse_data_st.port, NULL, &res);
	if (ret != 0) {
		printf("Address resolution failed: %d\n", ret);
		return -errno;
	}
	__ASSERT(IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS),
		 "Application was built without support for TLS");

	if (http_parse_data_st.is_tls_enabled) {
		sec_tag_t sec_tag_list[] = {
			TLS_TAG_CA_CERTIFICATE,
		};

		printf("Creating TLS socket\n");
		*sock_ptr = zsock_socket(res->ai_family, res->ai_socktype, IPPROTO_TLS_1_2);
		if (*sock_ptr < 0) {
			goto error;
		}

		ret = zsock_setsockopt(*sock_ptr, SOL_TLS, TLS_SEC_TAG_LIST, sec_tag_list,
				       sizeof(sec_tag_list));
		if (ret < 0) {
			goto error;
		}

		/* NOTE: The customer must not proceed to production with this.*/
		ret = zsock_setsockopt(*sock_ptr, SOL_TLS, TLS_HOSTNAME, NULL, 0);
		if (ret < 0) {
			goto error;
		}
	} else {
		*sock_ptr = zsock_socket(res->ai_family, res->ai_socktype, IPPROTO_TCP);
		if (*sock_ptr < 0) {
			goto error;
		}
	}

	/* Connect to the server */
	ret = zsock_connect(*sock_ptr, res->ai_addr, res->ai_addrlen);
	if (ret < 0) {
		printf("Connection failed (%d): %s\n", -errno, strerror(errno));
		*sock_ptr = -1;
		goto error;
	}

	printf("Connected to %s:%s\n", http_parse_data_st.host, http_parse_data_st.port);
	zsock_freeaddrinfo(res);
	return *sock_ptr;

error:
	if (*sock_ptr >= 0) {
		zsock_close(*sock_ptr);
		*sock_ptr = -1;
	}
	zsock_freeaddrinfo(res);
	return -errno;
}

/*
 * @brief Download firmware chunk from server
 *
 * @param app_ctx_st Pointer to application context
 * @return int 0 on success, negative error code on failure
 */
static int download_firmware_chunk(struct app_ctx *app_ctx_st)
{
	int ret = 0;
	char range_header[64];
	const char *headers[2] = {range_header, NULL};
	struct http_request req = {.method = HTTP_GET,
				   .url = app_ctx_st->http_parse_data_st.path,
				   .header_fields = headers,
				   .host = app_ctx_st->http_parse_data_st.host,
				   .protocol = "HTTP/1.1",
				   .response = ota_http_response_cb,
				   .recv_buf = app_ctx_st->http_recv_buf,
				   .recv_buf_len = sizeof(app_ctx_st->http_recv_buf)};

	printf("Downloading bytes %d-%d...\n", app_ctx_st->ota_range_start_byte,
	       app_ctx_st->ota_range_end_byte);

	/* Prepare headers */
	snprintf(range_header, sizeof(range_header), "Range: bytes=%d-%d\r\n",
		 app_ctx_st->ota_range_start_byte, app_ctx_st->ota_range_end_byte);

	/* Send request */
	ret = http_client_req(app_ctx_st->sock, &req, HTTP_RESP_TIMEOUT_MS, (void *)app_ctx_st);
	if (ret < 0) {
		printf("HTTP request failed: status=%s, requested range=%d-%d\n", strerror(-ret),
		       app_ctx_st->ota_range_start_byte, app_ctx_st->ota_range_end_byte);
	}
	return ret;
}

/*
 * @brief Updates the HTTP range header for the next chunk download
 *
 * Calculates the byte range for the next chunk to be downloaded based on
 * current progress and total firmware size.
 *
 * @param app_ctx_st Pointer to application context
 * @return true if the full image has been received, false otherwise
 */
bool ota_update_http_range_header(struct app_ctx *app_ctx_st)
{
	bool received_full_img = false;

	if (app_ctx_st->ota_range_end_byte == (app_ctx_st->ota_image_size - 1)) {
		printf("received full image\n");
		received_full_img = true;
		return received_full_img;
	}
	app_ctx_st->ota_range_end_byte = app_ctx_st->ota_range_start_byte + CHUNK_SIZE - 1;
	if (app_ctx_st->ota_range_end_byte > app_ctx_st->ota_image_size) {
		app_ctx_st->ota_range_end_byte = app_ctx_st->ota_image_size - 1;
	}
	return received_full_img;
}

/*
 * @brief Process firmware update data packets
 *
 * @param otaf_image Pointer to firmware image data
 * @param length Length of the data in bytes
 * @return int Status code (0 on success, negative error code on failure)
 */
int ota_load_firmware(struct app_ctx *app_ctx_st)
{
	static bool first_packet = true;
	uint32_t status = 0;
	uint8_t *otaf_image = app_ctx_st->msg_c.buffer;
	uint16_t length = app_ctx_st->msg_c.length;

	/* Input validation */
	if (!otaf_image || length == 0) {
		printf("Invalid firmware data parameters\n");
		return -EINVAL;
	}

	/* Handle the first packet (header processing) */
	if (first_packet) {
		uint8_t ota_header_size = sizeof(sl_si91x_firmware_header_t);

		/* Get firmware size from header */
		status = sl_wifi_get_firmware_size((void *)app_ctx_st->msg_c.buffer,
						   &app_ctx_st->ota_image_size);
		if (status != SL_STATUS_OK) {
			printf("Unable to fetch firmware size. Status: 0x%x\n", status);
			zsock_close(app_ctx_st->sock);
			return status;
		}
		printf("Firmware size: %u bytes\n", app_ctx_st->ota_image_size);

		/* Process firmware header */
		status = sl_si91x_fwup_start(otaf_image);
		if (status != SL_STATUS_OK) {
			printf("Failed to load firmware header (0x%x)\n", status);
			return status;
		}

		/* Load first chunk (after header) */
		status = sl_si91x_fwup_load((otaf_image + ota_header_size),
					    (length - ota_header_size));
		if (status != SL_STATUS_OK) {
			printf("Failed to load first firmware chunk (0x%x)\n", status);
			return status;
		}

		/* Mark that we've processed the first packet */
		first_packet = false;
		return SL_STATUS_OK;
	}

	/* Handle subsequent packets */
	status = sl_si91x_fwup_load(otaf_image, length);

	/* Check if firmware update is completed */
	if (status == SL_STATUS_SI91X_FW_UPDATE_DONE) {
		printf("Firmware update completed\n");
		zsock_close(app_ctx_st->sock);
		osDelay(3000);
		printf("SoC Soft Reset initiated!\n");
		sys_arch_reboot();

		/* Reset first_packet for next update session */
		first_packet = true;
		return SL_STATUS_OK;
	} else if (status != SL_STATUS_OK) {
		printf("Fail to load the firmware chunk: 0x%x\n", status);
		return status;
	}
	return SL_STATUS_OK;
}

/*
 * @brief Process downloaded firmware chunk
 * @param app_ctx_st Pointer to application context
 * @return int 0 if more chunks needed, 1 if complete, negative on error
 */
static int process_firmware_chunk(struct app_ctx *app_ctx_st)
{
	int status;
	int req_start;

	printf("Processing firmware data...\n");

	/* Wait for HTTP response to be fully received */
	if (k_sem_take(&app_ctx_st->ota_sem, K_MSEC(FW_CHUNK_DOWNLOAD_TIMEOUT_MS)) != 0) {
		printf("Firmware download failed or Semaphore timed out\n");
		return -errno;
	}

	/* Check if there was an error in the HTTP response */
	if (app_ctx_st->http_response_error) {
		printf("Error occurred during HTTP download, skipping processing\n");
		return -EPROTO;
	}
	req_start = app_ctx_st->ota_range_start_byte;

	/* Process all queued data chunks */
	while (k_msgq_get(&app_ctx_st->http_data_q, &app_ctx_st->msg_c, K_NO_WAIT) == 0) {
		app_ctx_st->ota_range_start_byte =
			app_ctx_st->ota_range_start_byte + app_ctx_st->msg_c.length;
		status = ota_load_firmware(app_ctx_st);
		if (status != SL_STATUS_OK) {
			printf("Fw load failed for requested range=%d-%d\n", req_start,
			       app_ctx_st->ota_range_end_byte);
			app_ctx_st->ota_range_start_byte = req_start;
			return -EIO;
		}
	}
	printf("Fw load success for requested range=%d-%d\n", req_start,
	       app_ctx_st->ota_range_end_byte);
	return 0;
}

/*
 * @brief Prints the current firmware version
 *
 * Retrieves and displays the current firmware version information
 * from the device.
 */
void ota_print_firmware_version(void)
{
	int ret = 0;
	sl_wifi_firmware_version_t version = {};

	/* Get initial firmware version */
	ret = sl_wifi_get_firmware_version(&version);
	if (ret == SL_STATUS_OK) {
		print_firmware_version(&version);
	} else {
		printf("Failed to get firmware version: 0x%x\n", ret);
	}
}

/*
 * @brief Clean up resources used by the OTA update process
 *
 * @param app_ctx_st Pointer to application context structure containing resources to clean up
 */
void ota_cleanup_resources(struct app_ctx *app_ctx_st)
{
	if (app_ctx_st->sock >= 0) {
		zsock_close(app_ctx_st->sock);
		app_ctx_st->sock = -1;
	}
	k_msgq_purge(&app_ctx_st->http_data_q);
	app_ctx_st->http_response_error = false;
	app_ctx_st->ipv6_addr_config_done = false;
}

/*
 * @brief Handles retry logic for OTA operations
 *
 * Manages retry attempts for various OTA operations, with appropriate
 * cleanup between attempts.
 *
 * @param app_ctx_st Pointer to application context
 * @param operation_name Name of the operation being retried for logging
 * @param cleanup_socket Whether to clean up socket resources before retrying
 * @return true if retry should continue, false if max retries exceeded
 */
static bool handle_retry(struct app_ctx *app_ctx_st, const char *operation_name,
			 bool cleanup_socket)
{
	static uint8_t retry_count;

	/* Clean up socket and message queue if needed */
	if (cleanup_socket && app_ctx_st->sock >= 0) {
		ota_cleanup_resources(app_ctx_st);
	}
	if (++retry_count > MAX_RETRIES) {
		printf("Maximum retries exceeded, aborting OTA\n");
		retry_count = 0;
		return false;
	}
	printf("Retrying %s (%d/%d)...\n", operation_name, retry_count, MAX_RETRIES);
	k_sleep(K_MSEC(1000));
	return true;
}

/*
 * @brief Main OTA application state machine
 * @param app_ctx_st Pointer to application context
 */
static void ota_application_start(struct app_ctx *app_ctx_st)
{
	int ret = 0;
	int firmware_status = 0;
	char *ssid = CONFIG_OTA_WIFI_SSID;
	char *pwd = CONFIG_OTA_WIFI_PSK;
	bool ota_complete = false;

	printf("OTA Application Started\n");
	ota_print_firmware_version();

	/* Main state machine loop */
	while (1) {
		switch (app_ctx_st->state) {
		case OTA_STATE_SCAN:
			ret = wifi_start_scan(app_ctx_st);
			break;
		case OTA_STATE_CONNECT:
			ret = wifi_connect(ssid, pwd, CONFIG_OTA_WIFI_SECURITY_TYPE, app_ctx_st);
			if (ret < 0) {
				if (!handle_retry(app_ctx_st, "Wi-Fi connection", false)) {
					return;
				}
				break;
			}
			break;

		case OTA_STATE_IP_CONFIG:
			ret = configure_ip(app_ctx_st);
			if (ret < 0) {
				if (!handle_retry(app_ctx_st, "IP configuration", false)) {
					return;
				}
				break;
			}
			app_ctx_st->state = OTA_STATE_SERVER_CONNECT;
			break;

		case OTA_STATE_SERVER_CONNECT:
			if ((CONFIG_OTA_IP_PROTOCOL_SELECTION == 1) &&
			    !app_ctx_st->ipv6_addr_config_done) {
				k_sleep(K_MSEC(10));
				break;
			}

			/* Parse URL for OTA server */
			if (ota_parse_url(&app_ctx_st->http_parse_data_st)) {
				printf("Failed to parse OTA URL, check configuration\n");
				if (!handle_retry(app_ctx_st, "URL parsing", false)) {
					return;
				}
				break;
			}

			if (app_ctx_st->http_parse_data_st.is_tls_enabled) {
				if (tls_credential_add(TLS_TAG_CA_CERTIFICATE,
						       TLS_CREDENTIAL_CA_CERTIFICATE, ca_cert_der,
						       ca_cert_der_len)) {
					printf("Failed to register CA certificate\n");
					return;
				}
				printf("CA Certificate added\n");
			}

			ret = connect_to_ota_server(app_ctx_st);
			if (ret < 0) {
				if (!handle_retry(app_ctx_st, "server connection", false)) {
					return;
				}
				break;
			}
			app_ctx_st->state = OTA_STATE_DOWNLOAD;
			break;

		case OTA_STATE_DOWNLOAD:
			ret = download_firmware_chunk(app_ctx_st);
			if (ret < 0) {
				if (!handle_retry(app_ctx_st, "download", true)) {
					return;
				}
				app_ctx_st->state = OTA_STATE_SERVER_CONNECT;
				break;
			}
			app_ctx_st->state = OTA_STATE_PROCESS;
			break;

		case OTA_STATE_PROCESS:
			firmware_status = process_firmware_chunk(app_ctx_st);
			if (firmware_status < 0) {
				printf("OTA update failed during processing\n");

				/* Determine next state based on error type */
				app_ctx_st->state = (firmware_status == -ETIMEDOUT)
							    ? OTA_STATE_SERVER_CONNECT
							    : OTA_STATE_DOWNLOAD;

				const char *operation = (firmware_status == -ETIMEDOUT)
								? "server connection"
								: "download";
				if (!handle_retry(app_ctx_st, operation, true)) {
					return;
				}
				break;
			}

			/* Update range and check if complete */
			ota_complete = ota_update_http_range_header(app_ctx_st);
			if (ota_complete) {
				printf("OTA update completed successfully\n");
				ota_cleanup_resources(app_ctx_st);
				return;
			}
			/* Get next chunk if OTA not complete*/
			app_ctx_st->state = OTA_STATE_DOWNLOAD;
			break;
		}
	}
}

/**
 * @brief Converts MAC address to string format
 *
 * @param mac Pointer to MAC address bytes
 * @param mac_len Length of MAC address (must be 6)
 * @param buf Buffer to store the string representation
 * @param buf_len Length of the buffer (must be at least 18 bytes)
 * @return Pointer to the buffer containing the string on success, NULL on failure
 */
static char *mac_to_string(const uint8_t *mac, uint8_t mac_len, char *buf, size_t buf_len)
{
	if (!mac || mac_len != 6 || !buf || buf_len < 18) {
		return NULL;
	}
	snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3],
		 mac[4], mac[5]);
	return buf;
}

static void handle_wifi_scan_result(struct net_mgmt_event_callback *cb)
{
	static bool header_not_printed;
	const struct wifi_scan_result *entry = (const struct wifi_scan_result *)cb->info;
	uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];
	uint8_t ssid_print[WIFI_SSID_MAX_LEN + 1];
	static uint16_t scan_result_count;

	if (header_not_printed) {
		printf("%-4s | %-32s %-5s | %-13s | %-4s | %-15s | %-17s | %-8s\n", "Num", "SSID",
		       "(len)", "Chan (Band)", "RSSI", "Security", "BSSID", "MFP");
		header_not_printed = false;
	}

	strncpy(ssid_print, entry->ssid, sizeof(ssid_print) - 1);
	ssid_print[sizeof(ssid_print) - 1] = '\0';

	printf("%-4d | %-32s %-5u | %-4u (%-6s) | %-4d | %-15s | %-17s | %-8s\n",
	       scan_result_count++, ssid_print, entry->ssid_length, entry->channel,
	       wifi_band_txt(entry->band), entry->rssi, wifi_security_txt(entry->security),
	       ((entry->mac_length) ? mac_to_string(entry->mac, WIFI_MAC_ADDR_LEN, mac_string_buf,
						    sizeof(mac_string_buf))
				    : ""),
	       wifi_mfp_txt(entry->mfp));
}

static void handle_wifi_scan_done(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *app_ctx_st = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	if (status->status) {
		printf("Scan request failed (%d)\n", status->status);
	} else {
		printf("Scan request done\n");
		k_sem_give(&app_ctx_st->wlan_sem);
	}
	app_ctx_st->state = OTA_STATE_CONNECT;
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *app_ctx_st = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	if (status->status) {
		printf("Connection request failed (%d)\n", status->status);
	} else {
		printf("Connected to Wi-Fi\n");
		k_sem_give(&app_ctx_st->wlan_sem);
		app_ctx_st->state = OTA_STATE_IP_CONFIG;
	}
}

static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;
	struct app_ctx *app_ctx_st = CONTAINER_OF(cb, struct app_ctx, wlan_mgmt_cb);

	if (status->status) {
		printf("Disconnection request failed (%d)\n", status->status);
	} else {
		printf("Disconnection reason: %d\n", status->disconn_reason);

		/* Check if disconnection occurred during OTA process */
		if (app_ctx_st->state > OTA_STATE_IP_CONFIG) {
			printf("WiFi disconnected during OTA update, initiating reconnection\n");
			ota_cleanup_resources(app_ctx_st);

			/* Set state to reconnect */
			app_ctx_st->state = OTA_STATE_CONNECT;
		}
		k_sem_give(&app_ctx_st->wlan_sem);
	}
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				    struct net_if *iface)
{

	switch (mgmt_event) {
	case NET_EVENT_WIFI_SCAN_RESULT:
		handle_wifi_scan_result(cb);
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		handle_wifi_scan_done(cb);
		break;
	case NET_EVENT_WIFI_CONNECT_RESULT:
		handle_wifi_connect_result(cb);
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		handle_wifi_disconnect_result(cb);
		break;
	default:
		break;
	}
}

int main(void)
{
	static struct app_ctx app_ctx = {
		.wlan_sem = Z_SEM_INITIALIZER(app_ctx.wlan_sem, 0, 1),
		.ota_sem = Z_SEM_INITIALIZER(app_ctx.ota_sem, 0, 1),
		.dhcp_sem = Z_SEM_INITIALIZER(app_ctx.dhcp_sem, 0, 1),
		.http_data_q = Z_MSGQ_INITIALIZER(app_ctx.http_data_q, app_ctx.http_data_q_buffer,
						  sizeof(msg_t), HTTP_MSG_Q_MAX_SIZE),
		.sock = -1,
		.ota_range_end_byte = (CHUNK_SIZE - 1),
		.state = OTA_STATE_SCAN};

	app_ctx.iface = net_if_get_first_wifi();
	net_mgmt_init_event_callback(&app_ctx.wlan_mgmt_cb, wifi_mgmt_event_handler,
				     WIFI_SHELL_MGMT_EVENTS_COMMON);
	net_mgmt_add_event_callback(&app_ctx.wlan_mgmt_cb);

	net_mgmt_init_event_callback(&app_ctx.dhcp_mgmt_cb, dhcp_callback_handler,
				     NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&app_ctx.dhcp_mgmt_cb);
	net_mgmt_init_event_callback(&app_ctx.l4_cb, l4_event_handler, NET_EVENT_L4_IPV6_CONNECTED);
	net_mgmt_add_event_callback(&app_ctx.l4_cb);

	ota_application_start(&app_ctx);
	return 0;
}
