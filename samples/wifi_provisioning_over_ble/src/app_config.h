#define SUCCESS 0

#define WIFI_SHELL_MGMT_EVENTS_COMMON                                                              \
	(NET_EVENT_WIFI_SCAN_DONE | NET_EVENT_WIFI_DISCONNECT_COMPLETE |                           \
	 NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT | NET_EVENT_WIFI_TWT |   \
	 NET_EVENT_WIFI_RAW_SCAN_RESULT | NET_EVENT_WIFI_AP_ENABLE_RESULT |                        \
	 NET_EVENT_WIFI_AP_DISABLE_RESULT | NET_EVENT_WIFI_AP_STA_CONNECTED |                      \
	 NET_EVENT_WIFI_AP_STA_DISCONNECTED)

#ifdef CONFIG_WIFI_MGMT_RAW_SCAN_RESULTS_ONLY
#define WIFI_SHELL_MGMT_EVENTS (WIFI_SHELL_MGMT_EVENTS_COMMON)
#else
#define WIFI_SHELL_MGMT_EVENTS (WIFI_SHELL_MGMT_EVENTS_COMMON | NET_EVENT_WIFI_SCAN_RESULT)
#endif /* CONFIG_WIFI_MGMT_RAW_SCAN_RESULTS_ONLY */

static void start_dhcpv4_client(struct net_if *iface, void *user_data);
static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event,
				    struct net_if *iface);
