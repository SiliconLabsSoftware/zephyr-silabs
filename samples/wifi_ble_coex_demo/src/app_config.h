typedef enum wlan_app_state_e {
	WLAN_SCAN_STATE = 0,
	WLAN_NET_UP_STATE,
	WLAN_IP_CONFIG_STATE,
	WLAN_SOCKET_CREATE_STATE,
	WLAN_SEND_SOCKET_DATA_STATE,
	WLAN_SOCKET_CLOSE_STATE,
} wlan_app_state_t;

#define CMD_WAIT_TIME 180000
#define STACK_SIZE    2048
#define SUCCESS       0
#define STACK_SIZE_BT 2048 /*BT stack size*/

#define WIFI_SHELL_MGMT_EVENTS_COMMON                                                              \
	(NET_EVENT_WIFI_SCAN_DONE | NET_EVENT_WIFI_CONNECT_RESULT |                                \
	 NET_EVENT_WIFI_DISCONNECT_RESULT | NET_EVENT_WIFI_TWT | NET_EVENT_WIFI_RAW_SCAN_RESULT |  \
	 NET_EVENT_WIFI_AP_ENABLE_RESULT | NET_EVENT_WIFI_AP_DISABLE_RESULT |                      \
	 NET_EVENT_WIFI_AP_STA_CONNECTED | NET_EVENT_WIFI_AP_STA_DISCONNECTED)

#ifdef CONFIG_WIFI_MGMT_RAW_SCAN_RESULTS_ONLY
#define WIFI_SHELL_MGMT_EVENTS (WIFI_SHELL_MGMT_EVENTS_COMMON)
#else
#define WIFI_SHELL_MGMT_EVENTS (WIFI_SHELL_MGMT_EVENTS_COMMON | NET_EVENT_WIFI_SCAN_RESULT)
#endif /* CONFIG_WIFI_MGMT_RAW_SCAN_RESULTS_ONLY */
#define L4_EVENT_MASK (NET_EVENT_L4_IPV6_CONNECTED)

void application_start(void);
static void start_dhcpv4_client(struct net_if *iface, void *user_data);
static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event,
				    struct net_if *iface);
