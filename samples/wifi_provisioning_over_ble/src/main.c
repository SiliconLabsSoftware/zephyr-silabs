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
#include <stdlib.h>
#include <zephyr/sys/printk.h>
#include <zephyr/linker/sections.h>
#include <zephyr/random/random.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include "app_config.h"
#include "sl_wifi.h"
#include "wifi_app_util.h"

/*BLE Related*/
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/sys/byteorder.h>
#include <version.h>

#if defined(CONFIG_NET_TC_THREAD_COOPERATIVE)
#define THREAD_PRIORITY K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1)
#else
#define THREAD_PRIORITY K_PRIO_PREEMPT(8)
#endif

struct net_if *iface;
static struct net_mgmt_event_callback wifi_shell_mgmt_cb;
extern const struct wifi_mgmt_ops siwx917_mgmt;
static struct net_mgmt_event_callback mgmt_cb;
char ipv4_addr[NET_IPV4_ADDR_LEN] = {0};
char subnet[NET_IPV4_ADDR_LEN] = {0};
char router[NET_IPV4_ADDR_LEN] = {0};
uint8_t mac_string_buf[sizeof("xx:xx:xx:xx:xx:xx")];
uint8_t ssid_print[WIFI_SSID_MAX_LEN + 1];

/**
 * @brief Context structure that holds the state and control information
 * related to the Wi-Fi connection and scan process.
 * This structure is used to track the current Wi-Fi scan result,
 * *connection state, and the associated shell instance.
 **/
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

#define MAX_DATA_LEN 66 /*Maximum length of the attribute data*/

extern char *net_sprint_ll_addr_buf(const uint8_t *ll, uint8_t ll_len, char *buf, int buflen);

void app_task_handler(void);

static K_SEM_DEFINE(wifi_handle_sem, 0, 1);

static struct bt_conn *current_conn; /*Stores the current bluetooth connection reference*/
static struct bt_gatt_exchange_params
	mtu_exchange_params; /*Structure to hold Bluetooth GATT MTU exchange parameters*/

uint8_t bt_data_notify[247] = {0}; /*stores the bluetooth transmit data*/
uint8_t current_char2_data[MAX_DATA_LEN] = {
	0};                /*Buffer for storing data related to bluetooth characteristics*/
uint8_t wifi_connected;    /*Stores the current Wi-Fi connection status*/
			   /*(0 = disconnected, 1 = connected)*/
uint8_t pwd[MAX_DATA_LEN]; /*Buffer for storing the Wi-Fi password received*/
uint8_t ssid[50];          /*Buffer for storing the SSID (Wi-Fi network name)*/
uint8_t sec_type;          /*Stores the security type (e.g., WPA, WPA2) for the Wi-Fi*/
			   /*network*/

bool write_event_flag;

/* UUID of Custom Service and it's characteristic*/
#define BT_UUID_CUSTOM_SERVICE_VAL     BT_UUID_DECLARE_16(0xAABB)
#define BT_UUID_CUSTOM_IN_CHAR_VAL     BT_UUID_DECLARE_16(0x1AA1)
#define BT_UUID_CUSTOM_OUT_CHAR_VAL    BT_UUID_DECLARE_16(0x1BB1)
#define BT_UUID_CUSTOM_NOTIFY_CHAR_VAL BT_UUID_DECLARE_16(0x1CC1)

static struct ble_write_in_char {
	const uint8_t *data;
	uint16_t length;
} ble_gatt_write_char;

/*Advertsisng data*/
static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xBB, 0xAA),
};

/*scan response data*/
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

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
	} else {
		printk("Advertising successfully started\n");
	}
}

/**
 * @brief This function initiates a Wi-Fi disconnection request. It triggers the disconnection
 * process and updates the status based on the result of the disconnection attempt.
 * If the disconnection fails or is already in progress, it logs the appropriate message.
 * It also updates relevant flags and data to reflect the disconnection status.
 **/
void do_wifi_disconnect(void)
{
	context.disconnecting = true;
	int status = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);

	if (status) {
		context.disconnecting = false;

		if (status == -EALREADY) {
			printk("Already disconnected");
		} else {
			printk("Disconnect request failed");
		}
	}
	printk("Disconnection in progress......\n");
	current_char2_data[0] = 0x04;
	current_char2_data[1] = 0x01;
	wifi_connected = 0;
}

/**
 * @brief This function initiates a Wi-Fi connection using the provided SSID, security type,
 * and Pre-Shared Key (PSK). It prepares the connection parameters and requests
 * the network management subsystem to connect to the specified Wi-Fi network.
 * If the connection request fails, it logs the error and updates the connection status.
 **/
void do_wifi_connect(void)
{
	struct wifi_connect_req_params cnx_params = {
		.channel = WIFI_CHANNEL_ANY,
		.band = 0,
		.security = sec_type,
		.mfp = WIFI_MFP_DISABLE,
		.ssid = ssid,
		.ssid_length = strlen(ssid),
		.psk = pwd,
		.psk_length = strlen(pwd),
	};
	/* Configure MFP/credentials for WPA3 and mixed modes */
	if (sec_type == WIFI_SECURITY_TYPE_SAE_AUTO) {
		cnx_params.mfp = WIFI_MFP_REQUIRED;
		cnx_params.sae_password = pwd;
		cnx_params.sae_password_length = strlen(pwd);
		cnx_params.psk = NULL;
		cnx_params.psk_length = 0;
	} else if (sec_type == WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL) {
		cnx_params.mfp = WIFI_MFP_OPTIONAL;
	}
	context.connecting = true;

	int status = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cnx_params, sizeof(cnx_params));
	if (status != SUCCESS) {
		printk("Connection request failed with error: %d\n", status);
		context.connecting = false;
		current_char2_data[0] = 0x02;
		current_char2_data[1] = 0x00;
	}
}

/**
 * @brief This function handles incoming commands sent to the device via Bluetooth.
 * It processes the command based on the first byte of the input value (`value[0]`)
 * and takes appropriate actions, such as scanning for Wi-Fi networks, connecting
 * to Wi-Fi, retrieving WLAN status, or fetching the firmware version.
 **/
static void handle_in_commands(uint8_t *value, uint16_t len)
{

	switch (value[0]) {
	/*Scan command request*/
	case '3': {
		memset(current_char2_data, 0, sizeof(current_char2_data));
		printk("Received scan request\n");
		int status = 0;
		struct wifi_scan_params params = {0};

		status = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &params, sizeof(params));
		if (status != SUCCESS) {
			printk("Scan request failed\n");
		}
	} break;
	/*Sending SSID*/
	case '2': {
		memset(current_char2_data, 0, sizeof(current_char2_data));
		memset(ssid, 0, sizeof(ssid));
		strncpy((char *)ssid, (const char *)&value[3], len - 3);
		printk("Received the ssid: %s\n", ssid);
	} break;
	/*Sending Security type*/
	case '5': {
		/* Convert incoming security code to Zephyr enum */
		uint8_t app_code;

		memset(current_char2_data, 0, sizeof(current_char2_data));
		printk("In Security Request\n");

		app_code = (uint8_t)((value[3]) - '0');
		sec_type = wifi_app_map_security_from_siconnect(app_code);
		current_char2_data[0] = 0x07;
		current_char2_data[1] = 0x00;
		if (sec_type != 0) {
			break;
		}
		do_wifi_connect();
	} break;
	/*Sending PSK*/
	case '6': {
		memset(pwd, 0, sizeof(pwd));
		memset(current_char2_data, 0, sizeof(current_char2_data));
		strncpy((char *)pwd, (const char *)&value[3], len - 3);
		printk("PWD from ble app %s\n", pwd);
		current_char2_data[0] = 0x07;
		current_char2_data[1] = 0x00;
		do_wifi_connect();
	} break;
	/*WLAN Status Request*/
	case '7': {
		printk("WLAN status request received\n");
		memset(current_char2_data, 0, sizeof(current_char2_data));
		if (wifi_connected) {
			current_char2_data[0] = 0x07;
			current_char2_data[1] = wifi_connected;
		} else {
			current_char2_data[0] = 0x07;
			current_char2_data[1] = 0x00;
		}
	} break;
	/*WLAN disconnect request*/
	case '4': {
		printk("WLAN disconnect request received\n");
		memset(current_char2_data, 0, sizeof(current_char2_data));
		do_wifi_disconnect();
	} break;
	/*FW version request*/
	case '8': {
		printk("FW version request\n");
		memset(current_char2_data, 0, sizeof(current_char2_data));

		sl_wifi_firmware_version_t firmware_version = (sl_wifi_firmware_version_t){0};
		int status = sl_wifi_get_firmware_version(&firmware_version);
		current_char2_data[0] = 0x08;
		if (status == SL_STATUS_OK) {
			current_char2_data[1] = sizeof(sl_wifi_firmware_version_t);
			memcpy(&current_char2_data[2], &firmware_version,
			       sizeof(sl_wifi_firmware_version_t));
		} else {
			printk("sl_wifi_get_firmware_version failed: 0x%x\n", status);
			current_char2_data[1] = 0;
		}
	} break;
	default:
		printk("Default command case\n\n");
		break;
	}
}

void app_task_handler(void)
{
	while (1) {
		if (write_event_flag) {
			handle_in_commands((uint8_t *)ble_gatt_write_char.data,
					   ble_gatt_write_char.length);
			write_event_flag = false;
		}
		k_sem_take(&wifi_handle_sem, K_FOREVER);
	}
}

/**
 * @brief This function handles writing data to the IN characteristic in a Bluetooth
 * GATT server. It processes the incoming data and performs an action based on
 * the received commands
 **/
static ssize_t write_in_char(struct bt_conn *conn, const struct bt_gatt_attr *attr, const void *buf,
			     uint16_t len, uint16_t offset, uint8_t flags)
{
	ble_gatt_write_char.data = buf;
	ble_gatt_write_char.length = len;
	if (offset + len > MAX_DATA_LEN) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	write_event_flag = true;
	k_sem_give(&wifi_handle_sem);
	return len;
}

/**
 * @brief This function handles reading data from the OUT characteristic in a Bluetooth
 * GATT server. It provides the data stored in `current_char2_data` to the client
 * when a read request is made.
 **/
static ssize_t read_out_char(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
			     uint16_t len, uint16_t offset)
{
	const char *data = current_char2_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, data, MAX_DATA_LEN);
}

/* Primary Service and it's characteristics Declaration */
BT_GATT_SERVICE_DEFINE(
	wifi_ble_provisioning_service, BT_GATT_PRIMARY_SERVICE(BT_UUID_CUSTOM_SERVICE_VAL),
	BT_GATT_CHARACTERISTIC(BT_UUID_CUSTOM_IN_CHAR_VAL, BT_GATT_CHRC_WRITE, BT_GATT_PERM_WRITE,
			       NULL, write_in_char, NULL),
	BT_GATT_CHARACTERISTIC(BT_UUID_CUSTOM_OUT_CHAR_VAL, BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE, read_out_char, NULL, NULL),
	BT_GATT_CHARACTERISTIC(BT_UUID_CUSTOM_NOTIFY_CHAR_VAL,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_READ, NULL,
			       NULL, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE));

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
 * @return Returns the error code (0 for success, non-zero for failure).
 */
static int mtu_exchange(struct bt_conn *conn)
{
	int err;

	mtu_exchange_params.func = mtu_exchange_cb;
	err = bt_gatt_exchange_mtu(conn, &mtu_exchange_params);
	if (err) {
		printk("%s: MTU exchange failed (err %d)", __func__, err);
	}
	return err;
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
		printk("BLE Connected\n");
		if (current_conn) {
			bt_conn_unref(current_conn); /*Unreference any previous connection*/
		}
		current_conn = bt_conn_ref(conn); /*Store new connection*/
		(void)mtu_exchange(current_conn);
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
	printk("BLE Disconnected (reason 0x%02x)\n", reason);

	if (current_conn) {
		bt_conn_unref(current_conn);
		current_conn = NULL;
	}
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

/** @brief Initializes Bluetooth functionality and starts advertising for throughput testing.
 *  This function enables Bluetooth, and starts legacy advertising
 *  in connectable and scannable mode. It also starts the notification thread for throughput
 *testing.
 *
 *  @return Returns 0 if initialization is successful, or a non-zero error code if it fails.
 **/
int bt_init(void)
{
	int err;

	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return err;
	}
	printk("Bluetooth initialized\n");

	start_adv();
	return 0;
}

/**
 * @brief This function handles the DHCP callback event when a new IPv4 address is assigned
 *		to the interface. It processes the received DHCP information, including the assigned
 *		IP address, subnet mask, gateway, lease time, and MAC address. The function logs
 *		these details and also prepares the `current_char2_data` buffer with relevant data
 *		for further use (e.g., sending over Bluetooth).
 **/
static void dhcp_callback_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
				  struct net_if *iface)
{
	int i = 0;
	int k = 0;
	struct net_linkaddr *ll_iface = NULL;

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
		printk("Lease time[%d]: %u seconds", net_if_get_by_iface(iface),
		       iface->config.dhcpv4.lease_time);

		current_char2_data[0] = 0x02;
		current_char2_data[1] = 0x01;
		current_char2_data[2] = ',';

		ll_iface = net_if_get_link_addr(iface);
		if (ll_iface) {
			for (k = 0; k < 6; k++) {
				current_char2_data[k + 3] = ll_iface->addr[k];
			}
		} else {
			k = 6;
		}
		current_char2_data[k + 3] = ',';
		/*IP Address*/
		for (int j = 0; k < 10; k++, j++) {
			current_char2_data[k + 4] =
				iface->config.ip.ipv4->unicast[i].ipv4.address.in_addr.s4_addr[j];
		}
	}
}

/**
 * @brief This is the main entry point of the application.
 * The program performs the following initialization steps:
 *
 * 1. It retrieves the first available Wi-Fi network interface to be used for network communication.
 * 2. It sets up and registers event callbacks for handling Wi-Fi management events, such as Wi-Fi
 * connection status changes.
 * 3. It sets up and registers event callbacks for DHCP events, specifically to handle the event of
 * acquiring an IPv4 address.
 * 4. It initializes the Bluetooth subsystem, preparing the system to support Bluetooth
 * communication.
 *
 * After performing the initializations, the program enters an infinite loop, where it remains idle,
 * waiting indefinitely for events (Wi-Fi or DHCP-related) to trigger the registered event handlers.
 * The system will continue to run and handle events as they occur, without further action from the
 * main thread.
 */
int main(void)
{
	iface = net_if_get_first_wifi();

	net_mgmt_init_event_callback(&wifi_shell_mgmt_cb, wifi_mgmt_event_handler,
				     (WIFI_SHELL_MGMT_EVENTS));

	net_mgmt_add_event_callback(&wifi_shell_mgmt_cb);

	net_mgmt_init_event_callback(&mgmt_cb, dhcp_callback_handler, NET_EVENT_IPV4_ADDR_ADD);

	net_mgmt_add_event_callback(&mgmt_cb);
	bt_init();
	app_task_handler();
	return 0;
}

/**
 * @brief This function is responsible for starting the DHCPv4 client on a given network interface.
 * It is typically called to initiate the process of obtaining an IPv4 address from a DHCP server.
 *
 * Parameters:
 *  - iface: A pointer to the network interface on which the DHCP client will be started.
 *  - user_data: An unused parameter (for consistency in event callback signatures).
 *
 **/
static void start_dhcpv4_client(struct net_if *iface, void *user_data)
{
	ARG_UNUSED(user_data);

	printk("\r\nStart on %s: index=%d", net_if_get_device(iface)->name,
	       net_if_get_by_iface(iface));
	net_dhcpv4_start(iface);
}

/**
 * @brief This function handles the results of a Wi-Fi scan. It processes the scan result
 * and displays relevant information about the detected Wi-Fi networks, including
 * the SSID, channel, security mode, RSSI, and more. Additionally, it sends the
 * Wi-Fi scan results to a connected Bluetooth device via GATT notifications.
 *
 **/
static void handle_wifi_scan_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_scan_result *entry = (const struct wifi_scan_result *)cb->info;

	context.scan_result++;

	if (context.scan_result == 1U) {
		printk("\n%-4s | %-32s %-5s | %-13s | %-4s | %-15s | %-17s | %-8s\n", "Num", "SSID",
		       "(len)", "Chan (Band)", "RSSI", "Security", "BSSID", "MFP");
	}

	strncpy(ssid_print, entry->ssid, sizeof(ssid_print) - 1);
	ssid_print[sizeof(ssid_print) - 1] = '\0';

	printk("%-4d | %-32s %-5u | %-4u (%-6s) | %-4d | %-15s | %-17s | %-8s\n",
	       context.scan_result, ssid_print, entry->ssid_length, entry->channel,
	       wifi_band_txt(entry->band), entry->rssi, wifi_security_txt(entry->security),
	       ((entry->mac_length) ? net_sprint_ll_addr_buf(entry->mac, WIFI_MAC_ADDR_LEN,
							     mac_string_buf, sizeof(mac_string_buf))
				    : ""),
	       wifi_mfp_txt(entry->mfp));

	/*Sends scan results to mobile*/
	struct bt_conn *conn_ref = bt_conn_ref(current_conn);

	if (!conn_ref) {
		printk("Failed to get connection reference\n");
		return;
	}
	bt_data_notify[0] = wifi_app_map_security_to_siconnect(entry->security); /*Security mode*/
	bt_data_notify[1] = ',';
	strncpy((char *)bt_data_notify + 2, (const char *)entry->ssid, entry->ssid_length);
	bt_data_notify[entry->ssid_length + 2] = '\0';

	int err = bt_gatt_notify(conn_ref, &wifi_ble_provisioning_service.attrs[6], bt_data_notify,
				 entry->ssid_length + 2 + 1);
	if (err) {
		printk("Notification failed (err %d)\n", err);
	}
	if (current_conn) {
		bt_conn_unref(current_conn);
	}
}

/**
 * @brief This function handles the completion of a Wi-Fi scan. It checks the status of the
 * scan and prints an appropriate message. If the scan is successful, it indicates
 * that the scan results are displayed in the application. If the scan fails,
 * it prints an error message with the failure status.
 **/
static void handle_wifi_scan_done(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printk("Scan request failed (%d)\n", status->status);
	} else {
		printk("Displayed all the scanned devices in app\n");
	}

	context.scan_result = 0U;
}

/**
 * @brief This function handles the result of a Wi-Fi connection attempt. It checks the
 * connection status and performs actions accordingly. If the connection is successful,
 * it updates relevant flags, sends a notification, and starts the DHCP process.
 * If the connection fails, it logs the failure and resets relevant variables.
 **/
static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printk("Connection request failed (%d)\n", status->status);
		wifi_connected = 0;
		current_char2_data[0] = 0x02;
		current_char2_data[1] = 0x00;
	} else {
		printk("Connected to Wi-Fi\n");
		wifi_connected = 1;
		current_char2_data[0] = 0x07;
		current_char2_data[1] = wifi_connected;
		net_if_foreach(start_dhcpv4_client, NULL);
	}

	context.connecting = false;
}

/**
 * @brief This function handles the result of a Wi-Fi disconnection attempt. It checks the
 * disconnection status and logs an appropriate message based on whether the disconnection
 * was successful or failed.
 **/
static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (status->status) {
		printk("Disconnection request failed (%d)\n", status->status);
	} else {
		printk("Disconnection request done (%d)\n", status->status);
	}
}

/**
 * @brief This function handles various Wi-Fi management events such as scan results, connection
 * results, and disconnection events. Based on the event type, it invokes the appropriate
 * handler function to process the event. It supports multiple Wi-Fi-related events and
 * can be extended for additional event handling (e.g., raw scan results, signal changes).
 **/
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
