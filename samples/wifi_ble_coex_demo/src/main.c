/*
 * Copyright (c) 2025 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#define DT_DRV_COMPAT silabs_siwx917_wifi
#include <zephyr/logging/log.h>
#include <zephyr/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr/sys/printk.h>
#include <zephyr/linker/sections.h>
#include <zephyr/random/random.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include "app_config.h"
#include <zephyr/net/socket.h>

/*BLE Related*/
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#define SSID          "Hotspot"
#define PSK           "12345678"
#define SECURITY_TYPE 1
#define SERVER_PORT   5002
#define BUF_SIZE      1460
#define PACKETS_COUNT 1000

#define SERVER_ADDRESS "192.168.107.249"

static K_SEM_DEFINE(wlan_sem, 0, 1);

static K_SEM_DEFINE(ble_sem, 0, 1);
static struct k_thread wifi_task_handle;
static K_THREAD_STACK_DEFINE(wifi_stack, STACK_SIZE);

struct net_if *iface;
static struct net_mgmt_event_callback wifi_shell_mgmt_cb;
static struct net_mgmt_event_callback mgmt_cb;

char ipv4_addr[NET_IPV4_ADDR_LEN] = {0};
char subnet[NET_IPV4_ADDR_LEN] = {0};
char router[NET_IPV4_ADDR_LEN] = {0};
char *ssid;
char *pwd;

volatile uint8_t state;

uint8_t data_buffer[BUF_SIZE] = {0};
uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];
uint8_t ssid_print[WIFI_SSID_MAX_LEN + 1];
uint32_t sent_bytes;

static struct {
	const struct shell *sh;
	uint32_t scan_result;

	union {
		struct {
			uint8_t connecting: 1;
			uint8_t disconnecting: 1;
			uint8_t _unused: 6;
		};
		uint8_t all;
	};
} context;

/*Bluetooth Related*/
#define BT_BUF_SIZE 247 /*Bluetooth data buffer size*/

struct bt_conn *conn_ref;
static struct bt_conn *current_conn; /*Stores the current bluetooth connection reference*/
static bool notifications_enabled =
	false; /*Flag to track whether Bluetooth notifications are enabled*/
static struct bt_gatt_exchange_params
	mtu_exchange_params; /*Structure to hold Bluetooth GATT MTU exchange parameters*/

extern char *net_sprint_ll_addr_buf(const uint8_t *ll, uint8_t ll_len, char *buf, int buflen);
void throughput_data_notify(void);

uint8_t bt_data_buffer[BT_BUF_SIZE] = {0}; /*stores the bluetooth transmitted data*/

/*Variables to manage throughput testing*/
uint32_t bt_start;
uint32_t bt_now;
uint32_t bt_sent_bytes;
uint32_t bt_total_bytes_sent;

#define BLE_STATE_IDLE          0x00 /*Idle State*/
#define BLE_STATE_CONNECTED     0x01 /*Connected state*/
#define BLE_STATE_MTU_EXCHANGED 0x02 /*MTU Exchanged state*/
#define BLE_STATE_DISCONNECTED  0x03 /*Disconected state*/
#define BLE_STATE_START_NOTIFY  0x04 /*Notify state*/
uint8_t ble_state =
	BLE_STATE_IDLE; /*State variable to track the current state of Bluetooth connection*/

/* Custom service uuid */
#define BT_UUID_CUSTOM_SERVICE                                                                     \
	BT_UUID_DECLARE_128(0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      \
			    0x00, 0x00, 0x00, 0x00, 0x01)

/* Custom char UUID */
#define BT_UUID_CUSTOM_CHAR                                                                        \
	BT_UUID_DECLARE_128(0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      \
			    0x00, 0x00, 0x00, 0x00, 0x02)

/*Advertsisng data*/
static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01),
#if defined(CONFIG_BT_EXT_ADV)
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME, sizeof(CONFIG_BT_DEVICE_NAME) - 1),
#endif /* CONFIG_BT_EXT_ADV */
};

/*Scan response data*/
static const struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME, sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

/**
 * @brief Starts Bluetooth Low Energy (BLE) advertising.
 *
 * This function initiates the BLE advertising process by calling the
 * `bt_le_adv_start()` function with specified advertising parameters, such as
 * the advertising type (fast connectable advertising) and the advertising
 * data (ad) and scan response data (sd).
 *
 * It checks for errors in starting the advertising and logs the result.
 */
static void start_adv(void)
{
	int err;

	if (ble_state == BLE_STATE_IDLE) {
		err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd,
				      ARRAY_SIZE(sd));
		if (err) {
			printk("Advertising failed to start (err %d)\n", err);
		} else {
			printk("Advertising successfully started\n");
		}
	} else {
		ble_state = BLE_STATE_DISCONNECTED;
		k_sem_give(&ble_sem);
	}
}

/* @brief Callback function for handling changes in the
 *			Client Characteristic Configuration (CCC) descriptor.
 * This function is called when the CCC descriptor is updated
 *			(e.g., enabling or disabling notifications).
 * @param attr The Bluetooth GATT attribute associated with the CCC descriptor.
 * @param value The new value of the CCC descriptor.
 *			Tells whether notifications are enabled or disabled.
 */
static void throughput_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	notifications_enabled = (value == BT_GATT_CCC_NOTIFY);
	if (notifications_enabled) {
		printk("\n--BLE TX THROUGHPUT TEST START\n");
		ble_state = BLE_STATE_START_NOTIFY;
		k_sem_give(&ble_sem);
	}
}

/*Definition of a custom service and characteristic*/
BT_GATT_SERVICE_DEFINE(custom_svc, BT_GATT_PRIMARY_SERVICE(BT_UUID_CUSTOM_SERVICE),
		       BT_GATT_CHARACTERISTIC(BT_UUID_CUSTOM_CHAR, BT_GATT_CHRC_NOTIFY,
					      BT_GATT_PERM_NONE, NULL, NULL, &bt_data_buffer),
		       BT_GATT_CCC(throughput_ccc_cfg_changed,
				   BT_GATT_PERM_READ | BT_GATT_PERM_WRITE));

/* @brief Function to measure and print the Bluetooth throughput based on
 *			total bytes transmitted and test duration.
 * This function calculates the throughput in both bits per second (bps) and
 *			bytes per second (Bps), then prints the result to the console.
 *
 * @param total_num_of_bytes The total number of bytes transferred during the test.
 * @param test_timeout The test duration in milliseconds.
 */
void measure_and_print_bt_throughput(uint32_t total_num_of_bytes, uint32_t test_timeout)
{
	uint32_t duration = ((test_timeout) / sys_clock_hw_cycles_per_sec()); /*ms to sec*/
	uint32_t result = ((uint32_t)total_num_of_bytes * 8) / duration;      /*bytes to bps*/
	uint32_t result_Bps = ((uint32_t)total_num_of_bytes) / duration;      /*bytes to bps*/

	printk("\r\nBLE Throughput achieved @ %u bps (%u Bps) in %u sec successfully\r\n", result,
	       result_Bps, duration);
}

/* @brief BLE notification thread for sending data over Bluetooth.
 * This thread handles sending notifications via Bluetooth GATT when notifications are enabled.
 * It continuously updates the notification buffer and sends notifications to the connected peer.
 * The throughput is measured and printed after each transmission cycle.
 */
void throughput_data_notify(void)
{
	for (int i = 0; i < sizeof(bt_data_buffer); i++) {
		bt_data_buffer[i] = i;
	}
	bt_start = k_cycle_get_32();

	conn_ref = bt_conn_ref(current_conn);
	if (!conn_ref) {
		printk("Failed to get connection reference\n");
		return;
	}

	while (notifications_enabled) {
		int err = bt_gatt_notify(conn_ref, &custom_svc.attrs[2], bt_data_buffer,
					 (sizeof(bt_data_buffer) - 3));
		if (err) {
			printk("Notification failed (err %d)\n", err);
			bt_sent_bytes = 0;
		}
		bt_sent_bytes = (sizeof(bt_data_buffer) - 3);
		bt_total_bytes_sent = bt_total_bytes_sent + bt_sent_bytes;
		bt_now = k_cycle_get_32();
		if ((((bt_now - bt_start)) / sys_clock_hw_cycles_per_sec()) >= 15) {
			break;
		}
	}

	k_sleep(K_MSEC(10)); /*Adding a short delay to let the notification be sent*/
	printk("BLE_TX THROUGHPUT TEST FINISHED\n");
	measure_and_print_bt_throughput(bt_total_bytes_sent, (bt_now - bt_start));

	/*Reset counters for next test*/
	bt_total_bytes_sent = 0;
	bt_sent_bytes = 0;
	bt_conn_unref(conn_ref);
}

/** @brief Callback function for the MTU exchange process.
 *  This function is called when the MTU exchange procedure completes. It logs whether the MTU
 * exchange was successful or failed and prints the current MTU value for the connection.
 *
 * @param conn The Bluetooth connection instance for which the MTU exchange was performed.
 * @param err The error code from the MTU exchange procedure.
 * @param params The parameters related to the MTU exchange.
 */
static void mtu_exchange_cb(struct bt_conn *conn, uint8_t err,
			    struct bt_gatt_exchange_params *params)
{
	printk("%s: MTU exchange %s (%u)\n", __func__, err == 0U ? "successful" : "failed",
	       bt_gatt_get_mtu(conn));
}

/** @brief Initiates an MTU (Maximum Transmission Unit) exchange procedure for the given Bluetooth
 * connection. This function attempts to initiate an MTU exchange with the connected peer and logs
 * the result. It sets the callback function to handle the result of the MTU exchange.
 *
 * @param conn The Bluetooth connection for which the MTU exchange is initiated.
 *  @return Returns the error code (0 for success, non-zero for failure).
 */
static int mtu_exchange(struct bt_conn *conn)
{
	int err;
#if APP_LOG_EN
	printk("%s: Current MTU = %u\n", __func__, bt_gatt_get_mtu(conn));

	printk("%s: Exchange MTU...\n", __func__);
#endif

	mtu_exchange_params.func = mtu_exchange_cb;
	err = bt_gatt_exchange_mtu(conn, &mtu_exchange_params);
	if (err) {
		printk("%s: MTU Exchange already started %d", __func__, err);
	}

	return err;
}

/** @brief Updates the connection parameters for the given Bluetooth connection.
 *  This function sets the connection parameters (interval, latency, and timeout) to predefined
 * values and attempts to update the connection parameters using `bt_conn_le_param_update`.
 *
 * @param conn The Bluetooth connection for which the parameters will be updated.
 * @return Returns 0 if the connection parameters are updated successfully, or a non-zero error code
 * if it fails.
 */
static uint8_t conn_param_update(struct bt_conn *conn)
{
	struct bt_le_conn_param param = {
		.interval_min = 6,
		.interval_max = 6,
		.latency = 0,
		.timeout = 100,
	};

	int err;

	err = bt_conn_le_param_update(conn, &param);

	if (err < 0) {
		printk("Failed to update params: %d", err);
		return err;
	}
	return 0;
}

/** @brief Callback function that handles the result of a Bluetooth connection attempt.
 *  This function is called when a connection is successfully established or fails.
 *  It updates the current connection reference and initiates the MTU exchange if the connection is
 * successful.
 *
 *  @param conn The Bluetooth connection instance that was established or failed.
 *  @param err The error code that indicates the result of the connection attempt.
 *  A value of 0 indicates success, while non-zero values indicate failure.
 */
static void connected(struct bt_conn *conn, uint8_t err)
{
	if (!err) {
		printk("\nBLE Connected\n");

		if (current_conn) {
			bt_conn_unref(current_conn); /*Unreference any previous connection*/
		}

		current_conn = bt_conn_ref(conn); /*Store new connection*/
		ble_state = BLE_STATE_CONNECTED;
		k_sem_give(&ble_sem);
	} else {
		printk("Connection failed (err %d)\n", err);
	}
}

/** @brief Callback function that handles the disconnection of a Bluetooth connection.
 *  This function is called when a Bluetooth connection is disconnected,
 *	either by the local device or the peer.
 *
 * @param conn The Bluetooth connection instance that was disconnected.
 * @param reason The reason code that indicates why the disconnection occurred.
 *	The value is a standard Bluetooth error code.
 */
static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("\nBLE Disconnected (reason 0x%02x)\n", reason);

	if (current_conn) {
		bt_conn_unref(current_conn);
		current_conn = NULL;
	}

	notifications_enabled = false; /*Stop notifications*/
}

/** @brief The parameters for an LE connection have been updated.
 *
 * This callback notifies the application that the connection
 * parameters for an LE connection have been updated.
 *
 * @param conn Connection object.
 * @param interval Connection interval.
 * @param latency Connection latency.
 * @param timeout Connection supervision timeout.
 */
static void conn_param_updated_cb(struct bt_conn *conn, uint16_t interval, uint16_t latency,
				  uint16_t timeout)
{
	printk("Connection parameter updated: %p 0x%04X (%u us), 0x%04X, 0x%04X\n", conn, interval,
	       BT_CONN_INTERVAL_TO_US(interval), latency, timeout);
}

/* Register connection callbacks */
BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.le_param_updated = conn_param_updated_cb,
	.recycled = start_adv,
};

/** @brief Callback function for when the Maximum Transmission Unit (MTU) is updated.
 *  This function is triggered when the MTU value (both transmission and reception)
 *	is updated for the Bluetooth connection
 * It logs the updated MTU values and stores a reference to the current connection.
 *
 * @param conn The Bluetooth connection instance for which the MTU was updated.
 * @param tx The updated transmission MTU (Maximum Transmission Unit) in bytes.
 * @param rx The updated reception MTU in bytes.
 */
static void mtu_updated(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
	printk("Updated MTU: TX: %d RX: %d bytes\n", tx, rx);
	ble_state = BLE_STATE_MTU_EXCHANGED;
	k_sem_give(&ble_sem);
}

/*Register mtu updated callback*/
static struct bt_gatt_cb gatt_callbacks = {.att_mtu_updated = mtu_updated};

/** @brief Initializes Bluetooth functionality and starts advertising for throughput testing.
 *  This function enables Bluetooth, registers GATT callbacks, and starts legacy advertising
 *  in connectable and scannable mode. It also starts the notification thread for throughput
 *testing.
 *
 *  @return Returns 0 if initialization is successful, or a non-zero error code if it fails.
 **/
int bt_throughput_test_init(void)
{
	int err;

	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return err;
	}

	printk("Bluetooth initialized\n");
	bt_gatt_cb_register(&gatt_callbacks);
	start_adv();
	return 0;
}

static void dhcp_callback_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				  struct net_if *iface)
{
	int i = 0;

	if (mgmt_event != NET_EVENT_IPV4_ADDR_ADD) {
		return;
	}

	for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {

		if (iface->config.ip.ipv4->unicast[i].ipv4.addr_type != NET_ADDR_DHCP) {
			continue;
		}

		printf("   Address[%d]: %s", net_if_get_by_iface(iface),
		       net_addr_ntop(AF_INET,
				     &iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr,
				     ipv4_addr, sizeof(ipv4_addr)));
		printf("    Subnet[%d]: %s", net_if_get_by_iface(iface),
		       net_addr_ntop(AF_INET, &iface->config.ip.ipv4->unicast[i].netmask, subnet,
				     sizeof(subnet)));
		printf("    Router[%d]: %s", net_if_get_by_iface(iface),
		       net_addr_ntop(AF_INET, &iface->config.ip.ipv4->gw, router, sizeof(router)));
		printf("Lease time[%d]: %u seconds", net_if_get_by_iface(iface),
		       iface->config.dhcpv4.lease_time);

		k_sem_give(&wlan_sem);
	}
}

int main(void)
{
	printf("\r\nWIFI and BLE Coex Application using zephyr native mode\r\n");
	bt_throughput_test_init(); /*enables ble and advertises.*/
	iface = net_if_get_first_wifi();

	net_mgmt_init_event_callback(&wifi_shell_mgmt_cb, wifi_mgmt_event_handler,
				     (WIFI_SHELL_MGMT_EVENTS));
	net_mgmt_add_event_callback(&wifi_shell_mgmt_cb);

	net_mgmt_init_event_callback(&mgmt_cb, dhcp_callback_handler, NET_EVENT_IPV4_ADDR_ADD);

	net_mgmt_add_event_callback(&mgmt_cb);

	k_tid_t my_tid = k_thread_create(&wifi_task_handle, wifi_stack, STACK_SIZE,
					 (k_thread_entry_t)application_start, NULL, NULL, NULL,
					 K_PRIO_PREEMPT(0), 0, K_FOREVER);

	k_sleep(K_MSEC(1000));
	k_thread_start(&wifi_task_handle);

	while (1) {
		if (k_sem_take(&ble_sem, K_FOREVER) != SUCCESS) {
			printk("\r\nWi-Fi Scan failed or semaphore timed out\r\n");
			ble_state = BLE_STATE_IDLE;
		}
		if (ble_state == BLE_STATE_CONNECTED) {
			/*start mtu exchange*/
			if (mtu_exchange(current_conn) == 0) {
				printk("MTU exchange started\n");
			} else {
				printk("MTU exchange failed\n");
			}
		} else if (ble_state == BLE_STATE_MTU_EXCHANGED) {
			/*Update conn parameters*/
			if (conn_param_update(current_conn) == 0) {
				printk("Connection parameters update request started\n");
			} else {
				printk("connection parameter update failed\n");
			}
		} else if (ble_state == BLE_STATE_START_NOTIFY) {
			throughput_data_notify();
		} else if (ble_state == BLE_STATE_DISCONNECTED) {
			break;
		}
	}
	k_thread_join(my_tid, K_FOREVER);
	printk("\r\nApplication exit\r\n");
	return 0;
}

void application_start(void)
{
	int client_socket = -1;
	int return_value = 0;
	int status = -1;
	int sent_bytes;
	uint32_t total_packets_sent = 0;
	struct sockaddr_in server_address = {0};

	printf("Wifi Application started\n");
	state = WLAN_SCAN_STATE;

	while (1) {
		switch (state) {
		case WLAN_SCAN_STATE: {
			struct wifi_scan_params params = {0};

			params.dwell_time_active = 99;
			status = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &params, sizeof(params));
			if (status != SUCCESS) {
				printf("Scan request failed\n");
				state = WLAN_SCAN_STATE;
				break;
			}

			printf("Scan requested\n");
			if (k_sem_take(&wlan_sem, K_MSEC(CMD_WAIT_TIME)) != SUCCESS) {
				printf("\r\nWi-Fi Scan failed or Semaphore timed out\r\n");
				state = WLAN_SCAN_STATE;
			}
		} break;

		case WLAN_NET_UP_STATE: {
			struct wifi_connect_req_params *cnx_params = NULL;

			cnx_params = malloc(sizeof(struct wifi_connect_req_params));
			if (cnx_params == NULL) {
				printf("\r\nmalloc failed\r\n");
				return;
			}
			memset(cnx_params, 0, sizeof(struct wifi_connect_req_params));
			context.connecting = true;
			ssid = SSID;
			pwd = PSK;
			cnx_params->channel = WIFI_CHANNEL_ANY;
			cnx_params->band = 0;
			cnx_params->security = SECURITY_TYPE;
			cnx_params->psk_length = strlen(PSK);
			cnx_params->psk = pwd;
			cnx_params->ssid_length = strlen(SSID);
			cnx_params->ssid = ssid;

			status = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, cnx_params,
					  sizeof(struct wifi_connect_req_params));
			if (status != SUCCESS) {
				printf("Connection request failed with error: %d\n", status);
				context.connecting = false;
				state = WLAN_NET_UP_STATE;
				free(cnx_params);
				cnx_params = NULL;
				break;
			}
			printf("Connection requested\n");

			if (k_sem_take(&wlan_sem, K_MSEC(CMD_WAIT_TIME)) != SUCCESS) {
				printf("\r\nWi-Fi connect failed\r\n");
				state = WLAN_NET_UP_STATE;
			}
			free(cnx_params);
			cnx_params = NULL;
		} break;

		case WLAN_IP_CONFIG_STATE: {
			net_if_foreach(start_dhcpv4_client, NULL);
			if (k_sem_take(&wlan_sem, K_MSEC(CMD_WAIT_TIME)) != SUCCESS) {
				printf("\r\nIP config failed\r\n");
				state = WLAN_IP_CONFIG_STATE;
				break;
			}
			state = WLAN_SOCKET_CREATE_STATE;
		} break;

		case WLAN_SOCKET_CREATE_STATE: {
			client_socket = -1;
			return_value = 0;
			socklen_t socket_length = sizeof(struct sockaddr_in);

			memset(&server_address, 0, sizeof(struct sockaddr_in));
			server_address.sin_family = AF_INET;
			server_address.sin_port = htons(SERVER_PORT);
			inet_pton(AF_INET, SERVER_ADDRESS, &server_address.sin_addr);
			/*Create socket*/
			client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (client_socket < 0) {
				printf("\r\nSocket creation failed with bsd error: %d\r\n", errno);
				break;
			}
			printf("\r\nTCP Socket Create Success\r\n");

			/*Socket connect*/
			return_value = connect(client_socket, (struct sockaddr *)&server_address,
					       socket_length);
			if (return_value < 0) {
				printf("\r\nSocket connect failed with bsd error: %d\r\n", errno);
				state = WLAN_SOCKET_CLOSE_STATE;
				break;
			}
			printf("\r\nTCP Socket Connect Success\r\n");

			if (state == WLAN_SOCKET_CREATE_STATE) {
				state = WLAN_SEND_SOCKET_DATA_STATE;
			}
		} break;
		case WLAN_SEND_SOCKET_DATA_STATE: {
			for (size_t i = 0; i < BUF_SIZE; i++) {
				data_buffer[i] = 'A' + (i % 26);
			}
			/*send data*/
			printf("\r\nTCP_TX Throughput test start\r\n");
			while (total_packets_sent < PACKETS_COUNT) {
				sent_bytes =
					send(client_socket, data_buffer, sizeof(data_buffer), 0);
				if (sent_bytes < 0) {
					if (errno == ENOBUFS) {
						continue;
					}
					printf("\r\nSend failed with bsd error:%d\r\n", errno);
					if (errno == ENOTCONN) {
						state = WLAN_SOCKET_CREATE_STATE;
					}
					close(client_socket);
					break;
				}
				total_packets_sent = total_packets_sent + 1;
			}
			printf("\r\nTotal packets sent = %d\r\n", total_packets_sent);

			if (state == WLAN_SEND_SOCKET_DATA_STATE) {
				state = WLAN_SOCKET_CLOSE_STATE;
			}
		} break;
		case WLAN_SOCKET_CLOSE_STATE: {
			/*Socket close*/
			status = close(client_socket);
			if (status != 0) {
				printf("\r\nSocket close fail, status = %d, errno = %d\r\n", status,
				       errno);
				state = WLAN_SOCKET_CLOSE_STATE;
			} else {
				printf("\r\nSocket close success\r\n");
			}
			k_sleep(K_MSEC(1000));
			return;
		} break;
		}
	}
}

static void start_dhcpv4_client(struct net_if *iface, void *user_data)
{
	ARG_UNUSED(user_data);

	printf("\r\nStart on %s: index=%d", net_if_get_device(iface)->name,
	       net_if_get_by_iface(iface));
	net_dhcpv4_start(iface);
}

static void handle_wifi_scan_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_scan_result *entry = (const struct wifi_scan_result *)cb->info;

	context.scan_result++;

	if (context.scan_result == 1U) {
		printf("\n%-4s | %-32s %-5s | %-13s | %-4s | %-15s | %-17s | %-8s\n", "Num", "SSID",
		       "(len)", "Chan (Band)", "RSSI", "Security", "BSSID", "MFP");
	}

	strncpy(ssid_print, entry->ssid, sizeof(ssid_print) - 1);
	ssid_print[sizeof(ssid_print) - 1] = '\0';

	printf("%-4d | %-32s %-5u | %-4u (%-6s) | %-4d | %-15s | %-17s | %-8s\n",
	       context.scan_result, ssid_print, entry->ssid_length, entry->channel,
	       wifi_band_txt(entry->band), entry->rssi, wifi_security_txt(entry->security),
	       ((entry->mac_length) ? net_sprint_ll_addr_buf(entry->mac, WIFI_MAC_ADDR_LEN,
							     mac_string_buf, sizeof(mac_string_buf))
				    : ""),
	       wifi_mfp_txt(entry->mfp));
}

static void handle_wifi_scan_done(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printf("Scan request failed (%d)\n", status->status);
		state = WLAN_SCAN_STATE;
	} else {
		printf("Scan request done\n");
		state = WLAN_NET_UP_STATE;
	}

	context.scan_result = 0U;
	k_sem_give(&wlan_sem);
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printf("Connection request failed (%d)\n", status->status);
		state = WLAN_NET_UP_STATE;
	} else {
		printf("Connected to Wi-Fi\n");
		state = WLAN_IP_CONFIG_STATE;
	}

	context.connecting = false;
	k_sem_give(&wlan_sem);
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
		break;
	case NET_EVENT_WIFI_TWT:
		break;
#ifdef CONFIG_WIFI_MGMT_RAW_SCAN_RESULTS
	case NET_EVENT_WIFI_RAW_SCAN_RESULT:
		handle_wifi_raw_scan_result(cb);
		break;
#endif /* CONFIG_WIFI_MGMT_RAW_SCAN_RESULTS */
	case NET_EVENT_WIFI_AP_ENABLE_RESULT:
		break;
	case NET_EVENT_WIFI_AP_DISABLE_RESULT:
		break;
	case NET_EVENT_WIFI_AP_STA_CONNECTED:
		break;
	case NET_EVENT_WIFI_AP_STA_DISCONNECTED:
		break;
#ifdef CONFIG_WIFI_NM_WPA_SUPPLICANT_ROAMING
	case NET_EVENT_WIFI_SIGNAL_CHANGE:
		handle_wifi_signal_change(cb);
		break;
	case NET_EVENT_WIFI_NEIGHBOR_REP_COMP:
		handle_wifi_neighbor_rep_complete(cb);
		break;
#endif
	default:
		break;
	}
}
