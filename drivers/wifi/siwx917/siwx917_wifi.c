/*
 * Copyright (c) 2023 Antmicro
 * Copyright (c) 2024 Silicon Laboratories Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#define DT_DRV_COMPAT silabs_siwx917_wifi

#include <zephyr/net/offloaded_netdev.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <assert.h>

#include "sl_si91x_socket.h"
#include "sl_si91x_socket_utility.h"
#include "sl_wifi_callback_framework.h"
#include "sl_wifi.h"
#include "sl_net_si91x.h"
#include "sl_net.h"

BUILD_ASSERT(NUMBER_OF_BSD_SOCKETS < sizeof(uint32_t) * 8);
BUILD_ASSERT(NUMBER_OF_BSD_SOCKETS < SIZEOF_FIELD(sl_si91x_fd_set, __fds_bits) * 8);

LOG_MODULE_REGISTER(siwx917_wifi);

struct siwx917_dev {
	struct net_if *iface;
	enum wifi_iface_state state;
	scan_result_cb_t scan_res_cb;

	struct k_event fds_recv_event;
	sl_si91x_fd_set fds_watch;
	struct {
		net_context_recv_cb_t cb;
		void *user_data;
		struct net_context *context;
	} fds_cb[NUMBER_OF_BSD_SOCKETS];
};

NET_BUF_POOL_FIXED_DEFINE(siwx917_tx_pool, 1, NET_ETH_MTU, 0, NULL);
NET_BUF_POOL_FIXED_DEFINE(siwx917_rx_pool, 10, NET_ETH_MTU, 0, NULL);

/* SiWx917 does not use the standard struct sockaddr (despite it uses the same
 * name):
 *   - uses Little Endian for port number while Posix uses big endian
 *   - IPv6 addresses are bytes swapped
 * Note: this function allows to have in == out.
 */
static void siwx917_sockaddr_swap_bytes(struct sockaddr *out,
					const struct sockaddr *in, socklen_t in_len)
{
	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)in;
	struct sockaddr_in6 *out6 = (struct sockaddr_in6 *)out;
	int i;

	/* In Zephyr, size of sockaddr == size of sockaddr_storage
	 * (while in Posix sockaddr is smaller than sockaddr_storage).
	 */
	memcpy(out, in, in_len);
	if (in->sa_family == AF_INET6) {
		for (i = 0; i < ARRAY_SIZE(in6->sin6_addr.s6_addr32); i++) {
			out6->sin6_addr.s6_addr32[i] = ntohl(in6->sin6_addr.s6_addr32[i]);
		}
		out6->sin6_port = ntohs(in6->sin6_port);
	} else if (in->sa_family == AF_INET) {
		out6->sin6_port = ntohs(in6->sin6_port);
	}
}

static void siwx917_on_join_ipv4(struct siwx917_dev *sidev)
{
#ifdef CONFIG_NET_IPV4
	sl_net_ip_configuration_t ip_config4 = {
		.mode = SL_IP_MANAGEMENT_DHCP,
		.type = SL_IPV4,
	};
	struct in_addr addr4 = { };
	int ret;

	/* FIXME: support for static IP configuration */
	ret = sl_si91x_configure_ip_address(&ip_config4, SL_SI91X_WIFI_CLIENT_VAP_ID);
	if (!ret) {
		memcpy(addr4.s4_addr, ip_config4.ip.v4.ip_address.bytes, sizeof(addr4.s4_addr));
		/* FIXME: also report gateway (net_if_ipv4_router_add()) */
		net_if_ipv4_addr_add(sidev->iface, &addr4, NET_ADDR_DHCP, 0);
	} else {
		LOG_ERR("sl_si91x_configure_ip_address(): %#04x", ret);
	}
#endif
}

static void siwx917_on_join_ipv6(struct siwx917_dev *sidev)
{
#ifdef CONFIG_NET_IPV6
	sl_net_ip_configuration_t ip_config6 = {
		.mode = SL_IP_MANAGEMENT_DHCP,
		.type = SL_IPV6,
	};
	struct in6_addr addr6 = { };
	int ret, i;

	/* FIXME: support for static IP configuration */
	ret = sl_si91x_configure_ip_address(&ip_config6, SL_SI91X_WIFI_CLIENT_VAP_ID);
	if (!ret) {
		for (i = 0; i < ARRAY_SIZE(addr6.s6_addr32); i++) {
			addr6.s6_addr32[i] = ntohl(ip_config6.ip.v6.global_address.value[i]);
		}
		/* SiWx917 already take care of DAD and sending ND is not
		 * supported anyway.
		 */
		net_if_flag_set(sidev->iface, NET_IF_IPV6_NO_ND);
		/* FIXME: also report gateway and link local address */
		net_if_ipv6_addr_add(sidev->iface, &addr6, NET_ADDR_AUTOCONF, 0);
	} else {
		LOG_ERR("sl_si91x_configure_ip_address(): %#04x", ret);
	}
#endif
}

static unsigned int siwx917_on_join(sl_wifi_event_t event,
				    char *result, uint32_t result_size, void *arg)
{
	struct siwx917_dev *sidev = arg;

	if (*result != 'C') {
		/* TODO: report the real reason of failure */
		wifi_mgmt_raise_connect_result_event(sidev->iface, WIFI_STATUS_CONN_FAIL);
		sidev->state = WIFI_STATE_INACTIVE;
		return 0;
	}

	wifi_mgmt_raise_connect_result_event(sidev->iface, WIFI_STATUS_CONN_SUCCESS);
	sidev->state = WIFI_STATE_COMPLETED;

	siwx917_on_join_ipv4(sidev);
	siwx917_on_join_ipv6(sidev);

	return 0;
}

static int siwx917_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	sl_wifi_client_configuration_t wifi_config = {
		.bss_type = SL_WIFI_BSS_TYPE_INFRASTRUCTURE,
	};
	int ret;

	switch (params->security) {
	case WIFI_SECURITY_TYPE_NONE:
		wifi_config.security = SL_WIFI_OPEN;
		wifi_config.encryption = SL_WIFI_NO_ENCRYPTION;
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		wifi_config.security = SL_WIFI_WPA;
		wifi_config.encryption = SL_WIFI_DEFAULT_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_PSK:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_TKIP_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_PSK_SHA256:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_CCMP_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_SAE:
		/* TODO: Support the case where MFP is not required */
		wifi_config.security = SL_WIFI_WPA3;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	case WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL:
		wifi_config.security = SL_WIFI_WPA2;
		wifi_config.encryption = SL_WIFI_DEFAULT_ENCRYPTION;
		wifi_config.credential_id = SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID;
		break;
	/* Zephyr WiFi shell doesn't specify how to pass credential for these
	 * key managements.
	 */
	case WIFI_SECURITY_TYPE_WEP: /* SL_WIFI_WEP/SL_WIFI_WEP_ENCRYPTION */
	case WIFI_SECURITY_TYPE_EAP: /* SL_WIFI_WPA2_ENTERPRISE/<various> */
	case WIFI_SECURITY_TYPE_WAPI:
	default:
		return -ENOTSUP;
	}

	if (params->band != WIFI_FREQ_BAND_UNKNOWN && params->band != WIFI_FREQ_BAND_2_4_GHZ) {
		return -ENOTSUP;
	}

	if (params->psk_length) {
		sl_net_set_credential(SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID, SL_NET_WIFI_PSK,
				      params->psk, params->psk_length);
	}

	if (params->sae_password_length) {
		sl_net_set_credential(SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL_ID, SL_NET_WIFI_PSK,
				      params->sae_password, params->sae_password_length);
	}

	if (params->channel != WIFI_CHANNEL_ANY) {
		wifi_config.channel.channel = params->channel;
	}

	wifi_config.ssid.length = params->ssid_length,
	memcpy(wifi_config.ssid.value, params->ssid, params->ssid_length);

	ret = sl_wifi_connect(SL_WIFI_CLIENT_INTERFACE, &wifi_config, 0);
	if (ret != SL_STATUS_IN_PROGRESS) {
		return -EIO;
	}

	return 0;
}

static int siwx917_disconnect(const struct device *dev)
{
	struct siwx917_dev *sidev = dev->data;
	int ret;

	ret = sl_wifi_disconnect(SL_WIFI_CLIENT_INTERFACE);
	if (ret) {
		return -EIO;
	}
	sidev->state = WIFI_STATE_INACTIVE;
	return 0;
}

static void siwx917_report_scan_res(struct siwx917_dev *sidev, sl_wifi_scan_result_t *result,
				    int item)
{
	static const struct {
		int sl_val;
		int z_val;
	} security_convert[] = {
		{ SL_WIFI_OPEN,            WIFI_SECURITY_TYPE_NONE    },
		{ SL_WIFI_WEP,             WIFI_SECURITY_TYPE_WEP     },
		{ SL_WIFI_WPA,             WIFI_SECURITY_TYPE_WPA_PSK },
		{ SL_WIFI_WPA2,            WIFI_SECURITY_TYPE_PSK     },
		{ SL_WIFI_WPA3,            WIFI_SECURITY_TYPE_SAE     },
		{ SL_WIFI_WPA3_TRANSITION, WIFI_SECURITY_TYPE_SAE     },
		{ SL_WIFI_WPA_ENTERPRISE,  WIFI_SECURITY_TYPE_EAP     },
		{ SL_WIFI_WPA2_ENTERPRISE, WIFI_SECURITY_TYPE_EAP     },
	};
	struct wifi_scan_result tmp = {
		.channel = result->scan_info[item].rf_channel,
		.rssi = result->scan_info[item].rssi_val,
		.ssid_length = strlen(result->scan_info[item].ssid),
		.mac_length = sizeof(result->scan_info[item].bssid),
		.security = WIFI_SECURITY_TYPE_UNKNOWN,
		.mfp = WIFI_MFP_UNKNOWN,
		/* FIXME: fill .mfp, .band and .channel */
	};
	int i;

	memcpy(tmp.ssid, result->scan_info[item].ssid, tmp.ssid_length);
	memcpy(tmp.mac, result->scan_info[item].bssid, tmp.mac_length);
	for (i = 0; i < ARRAY_SIZE(security_convert); i++) {
		if (security_convert[i].sl_val == result->scan_info[item].security_mode) {
			tmp.security = security_convert[i].z_val;
		}
	}
	sidev->scan_res_cb(sidev->iface, 0, &tmp);
}

static unsigned int siwx917_on_scan(sl_wifi_event_t event, sl_wifi_scan_result_t *result,
				    uint32_t result_size, void *arg)
{
	struct siwx917_dev *sidev = arg;
	int i;

	if (!sidev->scan_res_cb) {
		return -EFAULT;
	}
	for (i = 0; i < result->scan_count; i++) {
		siwx917_report_scan_res(sidev, result, i);
	}
	sidev->scan_res_cb(sidev->iface, 0, NULL);
	sidev->state = WIFI_STATE_INACTIVE;
	return 0;
}

static int siwx917_scan(const struct device *dev, struct wifi_scan_params *z_scan_config,
			scan_result_cb_t cb)
{
	sl_wifi_scan_configuration_t sl_scan_config = { };
	struct siwx917_dev *sidev = dev->data;
	int ret;

	if (sidev->state != WIFI_STATE_INACTIVE) {
		return -EBUSY;
	}

	/* FIXME: fill sl_scan_config with values from z_scan_config */
	sl_scan_config.type = SL_WIFI_SCAN_TYPE_ACTIVE;
	sl_scan_config.channel_bitmap_2g4 = 0xFFFF;
	memset(sl_scan_config.channel_bitmap_5g, 0xFF, sizeof(sl_scan_config.channel_bitmap_5g));

	sidev->scan_res_cb = cb;
	ret = sl_wifi_start_scan(SL_WIFI_CLIENT_INTERFACE, NULL, &sl_scan_config);
	if (ret != SL_STATUS_IN_PROGRESS) {
		return -EIO;
	}
	sidev->state = WIFI_STATE_SCANNING;

	return 0;
}

static int siwx917_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct siwx917_dev *sidev = dev->data;
	int32_t rssi = -1;

	memset(status, 0, sizeof(*status));
	status->state = sidev->state;
	sl_wifi_get_signal_strength(SL_WIFI_CLIENT_INTERFACE, &rssi);
	status->rssi = rssi;
	return 0;
}

static int siwx917_sock_recv_sync(struct net_context *context,
				  net_context_recv_cb_t cb, void *user_data)
{
	struct net_if *iface = net_context_get_iface(context);
	int sockfd = (int)context->offload_context;
	struct net_pkt *pkt;
	struct net_buf *buf;
	int ret;

	pkt = net_pkt_rx_alloc_on_iface(iface, K_MSEC(100));
	if (!pkt) {
		return -ENOBUFS;
	}
	buf = net_buf_alloc(&siwx917_rx_pool, K_MSEC(100));
	if (!buf) {
		net_pkt_unref(pkt);
		return -ENOBUFS;
	}
	net_pkt_append_buffer(pkt, buf);

	ret = sl_si91x_recvfrom(sockfd, buf->data, NET_ETH_MTU, 0, NULL, NULL);
	if (ret < 0) {
		net_pkt_unref(pkt);
		ret = -errno;
	} else {
		net_buf_add(buf, ret);
		net_pkt_cursor_init(pkt);
		ret = 0;
	}
	if (cb) {
		cb(context, pkt, NULL, NULL, ret, user_data);
	}
	return ret;
}

static void siwx917_sock_on_recv(sl_si91x_fd_set *read_fd, sl_si91x_fd_set *write_fd,
				 sl_si91x_fd_set *except_fd, int status)
{
	/* When CONFIG_NET_SOCKETS_OFFLOAD is set, only one interface exist */
	struct siwx917_dev *sidev = net_if_get_default()->if_dev->dev->data;

	ARRAY_FOR_EACH(sidev->fds_cb, i) {
		if (SL_SI91X_FD_ISSET(i, read_fd)) {
			if (sidev->fds_cb[i].cb) {
				siwx917_sock_recv_sync(sidev->fds_cb[i].context,
						       sidev->fds_cb[i].cb,
						       sidev->fds_cb[i].user_data);
			} else {
				SL_SI91X_FD_CLR(i, &sidev->fds_watch);
				k_event_post(&sidev->fds_recv_event, 1U << i);
			}
		}
	}

	sl_si91x_select(NUMBER_OF_BSD_SOCKETS, &sidev->fds_watch, NULL, NULL, NULL,
			siwx917_sock_on_recv);
}

static int siwx917_sock_get(sa_family_t family, enum net_sock_type type,
			    enum net_ip_protocol ip_proto, struct net_context **context)
{
	struct siwx917_dev *sidev = net_if_get_default()->if_dev->dev->data;
	int sockfd;

	sockfd = sl_si91x_socket(family, type, ip_proto);
	if (sockfd < 0) {
		return -errno;
	}
	assert(!sidev->fds_cb[sockfd].cb);
	(*context)->offload_context = (void *)sockfd;
	return sockfd;
}

static int siwx917_sock_put(struct net_context *context)
{
	struct siwx917_dev *sidev = net_context_get_iface(context)->if_dev->dev->data;
	int sockfd = (int)context->offload_context;
	int ret;

	SL_SI91X_FD_CLR(sockfd, &sidev->fds_watch);
	memset(&sidev->fds_cb[sockfd], 0, sizeof(sidev->fds_cb[sockfd]));
	sl_si91x_select(NUMBER_OF_BSD_SOCKETS, &sidev->fds_watch, NULL, NULL, NULL,
			siwx917_sock_on_recv);
	ret = sl_si91x_shutdown(sockfd, 0);
	if (ret < 0) {
		ret = -errno;
	}
	return ret;
}

static int siwx917_sock_bind(struct net_context *context,
			     const struct sockaddr *addr, socklen_t addrlen)
{
	struct siwx917_dev *sidev = net_context_get_iface(context)->if_dev->dev->data;
	int sockfd = (int)context->offload_context;
	struct sockaddr addr_le;
	int ret;

	/* Zephyr tends to call bind() even if the TCP socket is a client. 917
	 * return an error in this case.
	 */
	if (net_context_get_proto(context) == IPPROTO_TCP &&
	    !((struct sockaddr_in *)addr)->sin_port) {
		return 0;
	}
	siwx917_sockaddr_swap_bytes(&addr_le, addr, addrlen);
	ret = sl_si91x_bind(sockfd, &addr_le, addrlen);
	if (ret) {
		return -errno;
	}
	/* WiseConnect refuses to run select on TCP listening sockets */
	if (net_context_get_proto(context) == IPPROTO_UDP) {
		SL_SI91X_FD_SET(sockfd, &sidev->fds_watch);
		sl_si91x_select(NUMBER_OF_BSD_SOCKETS, &sidev->fds_watch, NULL, NULL, NULL,
				siwx917_sock_on_recv);
	}
	return 0;
}

static int siwx917_sock_connect(struct net_context *context,
				const struct sockaddr *addr, socklen_t addrlen,
				net_context_connect_cb_t cb, int32_t timeout, void *user_data)
{
	struct siwx917_dev *sidev = net_context_get_iface(context)->if_dev->dev->data;
	int sockfd = (int)context->offload_context;
	struct sockaddr addr_le;
	int ret;

	printk("foo\n");
	/* sl_si91x_connect() always return immediately, so we ignore timeout */
	siwx917_sockaddr_swap_bytes(&addr_le, addr, addrlen);
	ret = sl_si91x_connect(sockfd, &addr_le, addrlen);
	if (ret) {
		ret = -errno;
	}
	SL_SI91X_FD_SET(sockfd, &sidev->fds_watch);
	sl_si91x_select(NUMBER_OF_BSD_SOCKETS, &sidev->fds_watch, NULL, NULL, NULL,
			siwx917_sock_on_recv);
	if (cb) {
		cb(context, ret, user_data);
	}
	return ret;
}

static int siwx917_sock_listen(struct net_context *context, int backlog)
{
	int sockfd = (int)context->offload_context;
	int ret;

	ret = sl_si91x_listen(sockfd, backlog);
	if (ret) {
		return -errno;
	}
	return 0;
}

static int siwx917_sock_accept(struct net_context *context,
			       net_tcp_accept_cb_t cb, int32_t timeout, void *user_data)
{
	struct siwx917_dev *sidev = net_context_get_iface(context)->if_dev->dev->data;
	int sockfd = (int)context->offload_context;
	struct net_context *newcontext;
	struct sockaddr addr_le;
	int ret;

	/* TODO: support timeout != K_FOREVER */
	assert(timeout < 0);

	ret = net_context_get(net_context_get_family(context),
			      net_context_get_type(context),
			      net_context_get_proto(context), &newcontext);
	if (ret < 0) {
		return ret;
	}
	/* net_context_get() calls siwx917_sock_get() but sl_si91x_accept() also
	 * allocates a socket.
	 */
	ret = siwx917_sock_put(newcontext);
	if (ret < 0) {
		return ret;
	}
	/* The iface is reset when getting a new context. */
	newcontext->iface = context->iface;
	ret = sl_si91x_accept(sockfd, &addr_le, sizeof(addr_le));
	if (ret < 0) {
		return -errno;
	}
	newcontext->flags |= NET_CONTEXT_REMOTE_ADDR_SET;
	newcontext->offload_context = (void *)ret;
	siwx917_sockaddr_swap_bytes(&newcontext->remote, &addr_le, sizeof(addr_le));

	SL_SI91X_FD_SET(ret, &sidev->fds_watch);
	sl_si91x_select(NUMBER_OF_BSD_SOCKETS, &sidev->fds_watch, NULL, NULL, NULL,
			siwx917_sock_on_recv);
	if (cb) {
		cb(newcontext, &addr_le, sizeof(addr_le), 0, user_data);
	}

	return 0;
}

static int siwx917_sock_sendto(struct net_pkt *pkt,
			       const struct sockaddr *addr, socklen_t addrlen,
			       net_context_send_cb_t cb, int32_t timeout, void *user_data)
{
	struct net_context *context = pkt->context;
	int sockfd = (int)context->offload_context;
	struct sockaddr addr_le;
	struct net_buf *buf;
	int ret;

	/* struct net_pkt use fragmented buffers while SiWx917 API need a
	 * continuous buffer.
	 */
	if (net_pkt_get_len(pkt) > NET_ETH_MTU) {
		LOG_ERR("unexpected buffer size");
		ret = -ENOBUFS;
		goto out_cb;
	}
	buf = net_buf_alloc(&siwx917_tx_pool, K_FOREVER);
	if (!buf) {
		ret = -ENOBUFS;
		goto out_cb;
	}
	if (net_pkt_read(pkt, buf->data, net_pkt_get_len(pkt))) {
		ret = -ENOBUFS;
		goto out_release_buf;
	}
	net_buf_add(buf, net_pkt_get_len(pkt));

	/* sl_si91x_sendto() always return immediately, so we ignore timeout */
	siwx917_sockaddr_swap_bytes(&addr_le, addr, addrlen);
	ret = sl_si91x_sendto(sockfd, buf->data, net_pkt_get_len(pkt), 0, &addr_le, addrlen);
	if (ret < 0) {
		ret = -errno;
		goto out_release_buf;
	}
	net_pkt_unref(pkt);

out_release_buf:
	net_buf_unref(buf);

out_cb:
	if (cb) {
		cb(pkt->context, ret, user_data);
	}
	return ret;
}

static int siwx917_sock_send(struct net_pkt *pkt,
			     net_context_send_cb_t cb, int32_t timeout, void *user_data)
{
	return siwx917_sock_sendto(pkt, NULL, 0, cb, timeout, user_data);
}

static int siwx917_sock_recv(struct net_context *context,
			     net_context_recv_cb_t cb, int32_t timeout, void *user_data)
{
	struct net_if *iface = net_context_get_iface(context);
	struct siwx917_dev *sidev = iface->if_dev->dev->data;
	int sockfd = (int)context->offload_context;
	int ret;

	ret = k_event_wait(&sidev->fds_recv_event, 1U << sockfd, false,
			   timeout < 0 ? K_FOREVER : K_MSEC(timeout));
	if (timeout == 0) {
		sidev->fds_cb[sockfd].context = context;
		sidev->fds_cb[sockfd].cb = cb;
		sidev->fds_cb[sockfd].user_data = user_data;
	} else {
		memset(&sidev->fds_cb[sockfd], 0, sizeof(sidev->fds_cb[sockfd]));
	}

	if (ret) {
		k_event_clear(&sidev->fds_recv_event, 1U << sockfd);
		ret = siwx917_sock_recv_sync(context, cb, user_data);
		SL_SI91X_FD_SET(sockfd, &sidev->fds_watch);
	}

	sl_si91x_select(NUMBER_OF_BSD_SOCKETS, &sidev->fds_watch, NULL, NULL, NULL,
			siwx917_sock_on_recv);
	return ret;
}

static struct net_offload siwx917_offload = {
	.get      = siwx917_sock_get,
	.put      = siwx917_sock_put,
	.bind     = siwx917_sock_bind,
	.listen   = siwx917_sock_listen,
	.connect  = siwx917_sock_connect,
	.accept   = siwx917_sock_accept,
	.sendto   = siwx917_sock_sendto,
	.send     = siwx917_sock_send,
	.recv     = siwx917_sock_recv,
};

static void siwx917_iface_init(struct net_if *iface)
{
	struct siwx917_dev *sidev = iface->if_dev->dev->data;
	sl_mac_address_t mac_addr;
	sl_status_t status;

	iface->if_dev->offload = &siwx917_offload;
	sidev->state = WIFI_STATE_INTERFACE_DISABLED;
	sidev->iface = iface;
	k_event_init(&sidev->fds_recv_event);

	sl_wifi_set_scan_callback(siwx917_on_scan, sidev);
	sl_wifi_set_join_callback(siwx917_on_join, sidev);
	sl_wifi_get_mac_address(SL_WIFI_CLIENT_INTERFACE, &mac_addr);
	net_if_set_link_addr(iface, mac_addr.octet, sizeof(mac_addr.octet), NET_LINK_ETHERNET);

	status = sl_net_init(SL_NET_WIFI_CLIENT_INTERFACE, NULL, NULL, NULL);
	if (status) {
		LOG_ERR("sl_net_init(): %#04x", status);
		return;
	}
	sidev->state = WIFI_STATE_INACTIVE;
}

static int siwx917_dev_init(const struct device *dev)
{
	return 0;
}

static enum offloaded_net_if_types siwx917_get_type(void)
{
	return L2_OFFLOADED_NET_IF_TYPE_WIFI;
}

static const struct wifi_mgmt_ops siwx917_mgmt = {
	.scan         = siwx917_scan,
	.connect      = siwx917_connect,
	.disconnect   = siwx917_disconnect,
	.iface_status = siwx917_status,
};

static const struct net_wifi_mgmt_offload siwx917_api = {
	.wifi_iface.iface_api.init = siwx917_iface_init,
	.wifi_iface.get_type = siwx917_get_type,
	.wifi_mgmt_api = &siwx917_mgmt,
};

static struct siwx917_dev siwx917_dev;
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, siwx917_dev_init, NULL, &siwx917_dev, NULL,
				  CONFIG_WIFI_INIT_PRIORITY, &siwx917_api, NET_ETH_MTU);

/* IRQn 74 is used for communication with co-processor */
Z_ISR_DECLARE(74, ISR_FLAG_DIRECT, IRQ074_Handler, 0);
