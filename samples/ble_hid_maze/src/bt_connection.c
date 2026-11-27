/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/att.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/input/input.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/types.h>

#include <zephyr/dt-bindings/input/input-event-codes.h>

#include "app_input.h"
#include "app_led.h"
#include "app_types.h"
#include "ble_hid_app.h"
#include "hid_mouse.h"

LOG_MODULE_REGISTER(bt_connection, LOG_LEVEL_INF);

/* Only connect to very near devices when pairing openly. */
#define RSSI_CONNECT_THRESHOLD    (-30)
#define PAIRING_MODE_TIMEOUT      K_SECONDS(60)
#define RECONNECT_DELAY           K_MSEC(1500)
#define SCAN_START_MAX_ATTEMPTS   3U
#define HIDS_REPORT_MAP_MAX_LEN   512U
#define SCAN_CANDIDATE_COUNT      4U
#define SCAN_CANDIDATE_MAX_AGE_MS 1000
#define DISCONNECT_RETRY_DELAY    K_SECONDS(1)
#define DISCONNECT_MAX_ATTEMPTS   3U
#define HID_REPORT_TYPE_INPUT     0x01

/*
 * This firmware acts as a BLE Central / HID client.
 *
 * Advertising is intentionally not handled here. A central scans and creates
 * connections. Advertising would only be relevant if this same image also
 * exposed a peripheral role.
 */

enum ble_link_state {
	BLE_LINK_DISABLED,
	BLE_LINK_ENABLING,
	BLE_LINK_IDLE,
	BLE_LINK_SCANNING,
	BLE_LINK_CONNECTING,
	BLE_LINK_CONNECTED,
	BLE_LINK_DISCOVERING,
	BLE_LINK_READY,
	BLE_LINK_DISCONNECTING,
	BLE_LINK_ERROR,
};

enum peer_compatibility {
	PEER_UNVERIFIED,
	PEER_MOUSE,
	PEER_UNSUPPORTED,
};

enum hids_failure {
	HIDS_FAILURE_RETRY,
	HIDS_FAILURE_UNSUPPORTED,
};

enum hids_discovery_step {
	HIDS_DISCOVERY_STEP_IDLE,
	HIDS_DISCOVERY_STEP_SERVICE,
	HIDS_DISCOVERY_STEP_REPORT_MAP,
	HIDS_DISCOVERY_STEP_READ_REPORT_MAP,
	HIDS_DISCOVERY_STEP_REPORT_CHAR,
	HIDS_DISCOVERY_STEP_REPORT_REFERENCE,
	HIDS_DISCOVERY_STEP_REPORT_CCC,
	HIDS_DISCOVERY_STEP_CONFIRM_MISSING,
	HIDS_DISCOVERY_STEP_SUBSCRIBE_REPORT,
	HIDS_DISCOVERY_STEP_PROTOCOL_MODE,
	HIDS_DISCOVERY_STEP_WRITE_PROTOCOL_MODE,
	HIDS_DISCOVERY_STEP_CTRL_POINT,
	HIDS_DISCOVERY_STEP_WRITE_CTRL_POINT,
	HIDS_DISCOVERY_STEP_DONE,
};

struct hid_report_candidate {
	uint16_t value_handle;
	uint16_t end_handle;
	uint16_t reference_handle;
	uint16_t ccc_handle;
	uint8_t properties;
};

struct hids_client_state {
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t report_map_handle;
	uint16_t report_handle;
	uint16_t ccc_handle;
	uint16_t protocol_mode_handle;
	uint16_t ctrl_point_handle;
	/* Zero means the characteristic iterator has reached the service end. */
	uint16_t report_search_handle;
	struct hid_report_candidate candidate;
	enum hids_discovery_step discovery_step;
	struct hid_mouse_parser mouse_parser;
	uint8_t report_map[HIDS_REPORT_MAP_MAX_LEN];
	size_t report_map_len;
};

struct scan_candidate {
	bt_addr_le_t addr;
	int64_t seen_ms;
	bool valid;
};

struct ble_hid_ctx {
	struct bt_conn *conn;
	enum ble_link_state state;

	bool pairing_mode;
	/* Retained until disconnect and bond removal have both succeeded. */
	bool forget_pending;
	bool bonded_addr_valid;
	bt_addr_le_t bonded_addr;
	enum peer_compatibility peer_compatibility;
	uint8_t disconnect_reason;
	uint8_t disconnect_attempts;
	uint8_t scan_start_attempts;
	bool rejected_addr_valid;
	bt_addr_le_t rejected_addr;
	struct scan_candidate scan_candidates[SCAN_CANDIDATE_COUNT];

	struct bt_uuid_16 discover_uuid;
	struct bt_uuid_16 read_uuid;
	struct bt_gatt_discover_params discover_params;
	struct bt_gatt_read_params read_params;
	struct bt_gatt_subscribe_params subscribe_params;
	struct hids_client_state hids;
	enum hids_discovery_step pending_discovery_step;
	bool hids_report_subscribed;

	struct k_work_delayable pairing_timeout_work;
	struct k_work_delayable reconnect_work;
	struct k_work_delayable hids_work;
	struct k_work_delayable disconnect_work;
};

static struct ble_hid_ctx ble_ctx = {
	.state = BLE_LINK_DISABLED,
	.discover_uuid = BT_UUID_INIT_16(0),
	.hids.discovery_step = HIDS_DISCOVERY_STEP_IDLE,
};

static struct bt_uuid_16 report_map_uuid = BT_UUID_INIT_16(BT_UUID_HIDS_REPORT_MAP_VAL);

static const bt_security_t target_sec = BT_SECURITY_L2;

static const struct bt_conn_le_create_param create_param_1m = BT_CONN_LE_CREATE_PARAM_INIT(
	BT_CONN_LE_OPT_NONE, BT_GAP_SCAN_FAST_INTERVAL, BT_GAP_SCAN_FAST_WINDOW);

static int hids_ctrl_point_write(uint8_t val);

static void start_scan(struct ble_hid_ctx *ctx);
static void stop_scan(struct ble_hid_ctx *ctx);
static void schedule_reconnect(struct ble_hid_ctx *ctx);
static int connect_to_addr(struct ble_hid_ctx *ctx, const bt_addr_le_t *addr);
static int hids_discovery_start(struct ble_hid_ctx *ctx, struct bt_conn *conn);
static void hids_discovery_failed(struct ble_hid_ctx *ctx, enum hids_failure failure,
				  const char *what, int err);
static void request_disconnect(struct ble_hid_ctx *ctx, uint8_t reason);
static void release_peer(struct ble_hid_ctx *ctx, struct bt_conn *conn);
static void disconnect_work_fn(struct k_work *work);
static void subscribe_func(struct bt_conn *conn, uint8_t err,
			   struct bt_gatt_subscribe_params *params);
static int hids_discover_step(struct ble_hid_ctx *ctx, struct bt_conn *conn,
			      enum hids_discovery_step step);
static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params);
static uint8_t notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
			   const void *data, uint16_t length);
static uint8_t report_map_read_func(struct bt_conn *conn, uint8_t err,
				    struct bt_gatt_read_params *params, const void *data,
				    uint16_t length);
static void reset_hids_state(struct ble_hid_ctx *ctx);
static void init_subscribe_params(struct ble_hid_ctx *ctx);
static void refresh_bond_state(struct ble_hid_ctx *ctx);
static void set_pairing_mode_internal(struct ble_hid_ctx *ctx, bool enable);
static void pairing_timeout_fn(struct k_work *work);
static void reconnect_work_fn(struct k_work *work);
static void hids_work_fn(struct k_work *work);
static void pairing_work_fn(struct k_work *work);
static void forget_work_fn(struct k_work *work);
static void request_forget_and_pair(struct ble_hid_ctx *ctx);
static void hids_schedule_step(struct ble_hid_ctx *ctx, enum hids_discovery_step step);

K_WORK_DEFINE(pairing_work, pairing_work_fn);
K_WORK_DEFINE(forget_work, forget_work_fn);

static const char *state_to_str(enum ble_link_state state)
{
	switch (state) {
	case BLE_LINK_DISABLED:
		return "disabled";
	case BLE_LINK_ENABLING:
		return "enabling";
	case BLE_LINK_IDLE:
		return "idle";
	case BLE_LINK_SCANNING:
		return "scanning";
	case BLE_LINK_CONNECTING:
		return "connecting";
	case BLE_LINK_CONNECTED:
		return "connected";
	case BLE_LINK_DISCOVERING:
		return "discovering";
	case BLE_LINK_READY:
		return "ready";
	case BLE_LINK_DISCONNECTING:
		return "disconnecting";
	case BLE_LINK_ERROR:
		return "error";
	default:
		return "unknown";
	}
}

static void set_state(struct ble_hid_ctx *ctx, enum ble_link_state state)
{
	if (ctx->state == state) {
		return;
	}

	LOG_INF("BLE state: %s -> %s", state_to_str(ctx->state), state_to_str(state));
	ctx->state = state;
}

static bool conn_is_current(const struct ble_hid_ctx *ctx, struct bt_conn *conn)
{
	return conn != NULL && ctx->conn == conn;
}

static bool adv_type_is_connectable(uint8_t adv_type)
{
	return adv_type == BT_GAP_ADV_TYPE_ADV_IND || adv_type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND ||
	       adv_type == BT_GAP_ADV_TYPE_EXT_ADV;
}

static bool peer_allowed(const struct ble_hid_ctx *ctx, const bt_addr_le_t *addr)
{
	if (ctx->forget_pending) {
		return false;
	}
	if (ctx->pairing_mode && ctx->rejected_addr_valid &&
	    bt_addr_le_cmp(addr, &ctx->rejected_addr) == 0) {
		return false;
	}

	if (ctx->bonded_addr_valid && !ctx->pairing_mode) {
		return bt_addr_le_cmp(addr, &ctx->bonded_addr) == 0;
	}

	return ctx->pairing_mode;
}

static bool hid_service_found(struct bt_data *data, void *user_data)
{
	bool *found = user_data;
	size_t uuid_size;

	switch (data->type) {
	case BT_DATA_UUID16_SOME:
	case BT_DATA_UUID16_ALL:
		uuid_size = BT_UUID_SIZE_16;
		break;
	case BT_DATA_UUID32_SOME:
	case BT_DATA_UUID32_ALL:
		uuid_size = BT_UUID_SIZE_32;
		break;
	case BT_DATA_UUID128_SOME:
	case BT_DATA_UUID128_ALL:
		uuid_size = BT_UUID_SIZE_128;
		break;
	default:
		return true;
	}

	if (data->data_len % uuid_size != 0U) {
		return true;
	}

	for (size_t offset = 0U; offset < data->data_len; offset += uuid_size) {
		struct bt_uuid_any uuid;

		if (bt_uuid_create(&uuid.uuid, &data->data[offset], uuid_size) &&
		    bt_uuid_cmp(&uuid.uuid, BT_UUID_HIDS) == 0) {
			*found = true;
			return false;
		}
	}

	return true;
}

static bool advertises_hid_service(const struct net_buf_simple *ad)
{
	struct net_buf_simple payload = *ad;
	bool found = false;

	bt_data_parse(&payload, hid_service_found, &found);
	return found;
}

static bool scan_peer_is_connectable(struct ble_hid_ctx *ctx, const bt_addr_le_t *addr,
				     uint8_t adv_type)
{
	struct scan_candidate *oldest = &ctx->scan_candidates[0];
	int64_t now = k_uptime_get();

	for (size_t i = 0U; i < ARRAY_SIZE(ctx->scan_candidates); i++) {
		struct scan_candidate *candidate = &ctx->scan_candidates[i];

		if (candidate->valid && bt_addr_le_cmp(addr, &candidate->addr) == 0) {
			if (adv_type_is_connectable(adv_type)) {
				candidate->seen_ms = now;
				return true;
			}
			if (adv_type == BT_GAP_ADV_TYPE_SCAN_RSP) {
				return now - candidate->seen_ms <= SCAN_CANDIDATE_MAX_AGE_MS;
			}
			candidate->valid = false;
			return false;
		}
		if (!candidate->valid || (oldest->valid && candidate->seen_ms < oldest->seen_ms)) {
			oldest = candidate;
		}
	}

	if (!adv_type_is_connectable(adv_type)) {
		return false;
	}

	/* Active scan responses can carry the service list in a separate packet. */
	oldest->addr = *addr;
	oldest->seen_ms = now;
	oldest->valid = true;
	return true;
}

static bool should_connect_to_device(struct ble_hid_ctx *ctx, const bt_addr_le_t *addr, int8_t rssi,
				     uint8_t adv_type, const struct net_buf_simple *ad)
{
	if (ctx->state != BLE_LINK_SCANNING) {
		return false;
	}

	if (ctx->conn != NULL) {
		return false;
	}

	/* Proximity filtering is only needed while accepting a new peer. */
	if (ctx->pairing_mode && rssi < RSSI_CONNECT_THRESHOLD) {
		return false;
	}

	if (!peer_allowed(ctx, addr) || !scan_peer_is_connectable(ctx, addr, adv_type)) {
		return false;
	}

	/* A known mouse may reconnect using directed advertising with no payload. */
	if (ctx->bonded_addr_valid && bt_addr_le_cmp(addr, &ctx->bonded_addr) == 0) {
		return true;
	}

	return advertises_hid_service(ad);
}

static void reset_hids_state(struct ble_hid_ctx *ctx)
{
	/*
	 * Do not clear subscribe_params here. Zephyr keeps a pointer to the
	 * bt_gatt_subscribe_params object while the subscription exists, and the
	 * object also participates in automatic cleanup/resubscribe logic. Clearing
	 * it on disconnect can erase the notify callback while the BT RX workqueue
	 * still owns the object, which results in a branch through address 0.
	 */
	(void)memset(&ctx->hids, 0, sizeof(ctx->hids));
	ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_IDLE;
	ctx->pending_discovery_step = HIDS_DISCOVERY_STEP_IDLE;
	ctx->hids_report_subscribed = false;
}

static void init_subscribe_params(struct ble_hid_ctx *ctx)
{
	(void)memset(&ctx->subscribe_params, 0, sizeof(ctx->subscribe_params));

	/*
	 * This client performs explicit discovery/subscription on every new link.
	 * Mark the subscription volatile so Zephyr removes it from the client
	 * subscription list on disconnect instead of trying to auto-resubscribe
	 * with handles discovered during the previous connection.
	 */
	atomic_set_bit(ctx->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
	atomic_set_bit(ctx->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_NO_RESUB);

	ctx->subscribe_params.notify = notify_func;
	ctx->subscribe_params.subscribe = subscribe_func;
	ctx->subscribe_params.value = BT_GATT_CCC_NOTIFY;
	ctx->subscribe_params.min_security = target_sec;
}

static void bond_pick_first(const struct bt_bond_info *info, void *user_data)
{
	struct ble_hid_ctx *ctx = user_data;

	/* Keep the first bond. With CONFIG_BT_MAX_PAIRED=1 this is the only bond. */
	if (!ctx->bonded_addr_valid) {
		ctx->bonded_addr = info->addr;
		ctx->bonded_addr_valid = true;
	}
}

static void refresh_bond_state(struct ble_hid_ctx *ctx)
{
	ctx->bonded_addr_valid = false;
	bt_foreach_bond(BT_ID_DEFAULT, bond_pick_first, ctx);

	if (ctx->bonded_addr_valid) {
		char addr[BT_ADDR_LE_STR_LEN];

		bt_addr_le_to_str(&ctx->bonded_addr, addr, sizeof(addr));
		LOG_INF("Bonded HID peer: %s", addr);
	} else {
		LOG_INF("No bonded HID peer");
	}
}

static void stop_scan(struct ble_hid_ctx *ctx)
{
	int err;

	if (ctx->state != BLE_LINK_SCANNING) {
		return;
	}

	err = bt_le_scan_stop();
	if (err && err != -EALREADY) {
		LOG_WRN("Scan stop failed: %d", err);
	}

	set_state(ctx, BLE_LINK_IDLE);
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	char addr_str[BT_ADDR_LE_STR_LEN];

	if (!should_connect_to_device(ctx, addr, rssi, type, ad)) {
		return;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	LOG_INF("Candidate HID peer: %s type %u RSSI %d", addr_str, type, rssi);

	(void)connect_to_addr(ctx, addr);
}

static void start_scan(struct ble_hid_ctx *ctx)
{
	int err;
	struct bt_le_scan_param scan_param = {
		.type = BT_LE_SCAN_TYPE_ACTIVE,
		.options = BT_LE_SCAN_OPT_NONE,
		.interval = BT_GAP_SCAN_FAST_INTERVAL,
		.window = BT_GAP_SCAN_FAST_WINDOW,
	};

	if (ctx->forget_pending || ctx->conn != NULL || ctx->state != BLE_LINK_IDLE) {
		return;
	}

	if (!ctx->bonded_addr_valid && !ctx->pairing_mode) {
		LOG_INF("Scan not started: no bond and pairing mode is disabled");
		return;
	}

	(void)memset(ctx->scan_candidates, 0, sizeof(ctx->scan_candidates));
	ctx->scan_start_attempts++;
	err = bt_le_scan_start(&scan_param, device_found);
	if (err && err != -EALREADY) {
		/* Invalid configuration cannot recover by repeating the same request. */
		if (err == -EINVAL || err == -ENOTSUP ||
		    ctx->scan_start_attempts >= SCAN_START_MAX_ATTEMPTS) {
			(void)k_work_cancel_delayable(&ctx->reconnect_work);
			set_state(ctx, BLE_LINK_ERROR);
			(void)app_led_set_pattern(APP_LED_PATTERN_ON);
			LOG_ERR("Scan start failed (%d) after %u attempt(s). Press Button0 "
				"to clear the bond and start fresh pairing",
				err, ctx->scan_start_attempts);
		} else {
			LOG_WRN("Scan start failed (%d), attempt %u/%u; retrying", err,
				ctx->scan_start_attempts, SCAN_START_MAX_ATTEMPTS);
			schedule_reconnect(ctx);
		}
		return;
	}

	ctx->scan_start_attempts = 0U;
	(void)k_work_cancel_delayable(&ctx->reconnect_work);
	set_state(ctx, BLE_LINK_SCANNING);
	LOG_INF("Scanning started");
}

static void schedule_reconnect(struct ble_hid_ctx *ctx)
{
	if (ctx->state != BLE_LINK_IDLE) {
		return;
	}

	if (ctx->forget_pending) {
		(void)k_work_submit(&forget_work);
		return;
	}

	if (!ctx->bonded_addr_valid && !ctx->pairing_mode) {
		LOG_INF("Reconnect not scheduled: no bond and pairing mode is disabled");
		return;
	}

	(void)k_work_schedule(&ctx->reconnect_work, RECONNECT_DELAY);
}

static void reconnect_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	/*
	 * Do not direct-connect to a bonded mouse that may be asleep.
	 * Scan first, then initiate only after a fresh advertisement.
	 * (Workaround for SiWx91x duplicate Command Complete after
	 * LE Create Connection Cancel)
	 */
	start_scan(&ble_ctx);
}

static int connect_with_params(struct ble_hid_ctx *ctx, const bt_addr_le_t *addr,
			       const struct bt_conn_le_create_param *param)
{
	int err;

	err = bt_conn_le_create(addr, param, BT_LE_CONN_PARAM_DEFAULT, &ctx->conn);
	if (err && ctx->conn != NULL) {
		bt_conn_unref(ctx->conn);
		ctx->conn = NULL;
	}

	return err;
}

static int connect_to_addr(struct ble_hid_ctx *ctx, const bt_addr_le_t *addr)
{
	int err;

	if (ctx->conn != NULL || ctx->state == BLE_LINK_CONNECTING) {
		return -EBUSY;
	}

	stop_scan(ctx);
	/* Claim the attempt before yielding so pairing changes cannot restart scanning. */
	set_state(ctx, BLE_LINK_CONNECTING);

	/* Give the controller a short gap between scan stop and initiate. */
	k_sleep(K_MSEC(100));

	/* Button0 or the pairing timeout may have changed the policy during the gap. */
	if (!peer_allowed(ctx, addr)) {
		set_state(ctx, BLE_LINK_IDLE);
		schedule_reconnect(ctx);
		return -ECANCELED;
	}
	ctx->peer_compatibility = PEER_UNVERIFIED;

	LOG_INF("Creating HID connection using 1M PHY");
	err = connect_with_params(ctx, addr, &create_param_1m);
	if (!err) {
		/* A forget request can arrive while LE Create Connection is pending. */
		if (ctx->forget_pending) {
			request_disconnect(ctx, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		}
		return 0;
	}

	LOG_ERR("Connection create failed: %d", err);
	set_state(ctx, BLE_LINK_IDLE);
	schedule_reconnect(ctx);

	return err;
}

static uint8_t notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params,
			   const void *data, uint16_t length)
{
	int err;
	struct mouse_data_element mouse_data;

	ARG_UNUSED(params);

	if (!conn_is_current(&ble_ctx, conn)) {
		return BT_GATT_ITER_STOP;
	}

	if (data == NULL) {
		LOG_INF("HID notifications unsubscribed");
		ble_ctx.hids_report_subscribed = false;
		return BT_GATT_ITER_STOP;
	}
	if (ble_ctx.state != BLE_LINK_READY) {
		return BT_GATT_ITER_CONTINUE;
	}

	LOG_HEXDUMP_DBG(data, length, "Input report");
	err = hid_mouse_decode_report(&ble_ctx.hids.mouse_parser, data, length, &mouse_data);
	if (err) {
		LOG_WRN("HID mouse decode failed: %d", err);
		return BT_GATT_ITER_CONTINUE;
	}

	LOG_DBG("L:%d R:%d x:%d y:%d", mouse_data.left_button, mouse_data.right_button,
		mouse_data.dx, mouse_data.dy);

	err = app_input_submit_mouse(&mouse_data);
	if (err) {
		LOG_WRN("Mouse input submit failed: %d", err);
		return BT_GATT_ITER_CONTINUE;
	}

	return BT_GATT_ITER_CONTINUE;
}

static uint8_t report_map_read_func(struct bt_conn *conn, uint8_t err,
				    struct bt_gatt_read_params *params, const void *data,
				    uint16_t length)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	int rc;

	ARG_UNUSED(params);

	if (!conn_is_current(ctx, conn) || ctx->state != BLE_LINK_DISCOVERING) {
		return BT_GATT_ITER_STOP;
	}

	if (err) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "Report Map read", err);
		return BT_GATT_ITER_STOP;
	}

	if (data == NULL) {

		LOG_INF("Report Map length: %u", ctx->hids.report_map_len);

		LOG_HEXDUMP_DBG(ctx->hids.report_map, ctx->hids.report_map_len, "HID Report Map");

		rc = hid_mouse_parser_init(&ctx->hids.mouse_parser, ctx->hids.report_map,
					   ctx->hids.report_map_len);
		if (rc) {
			hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED, "mouse Report Map",
					      rc);
			return BT_GATT_ITER_STOP;
		}

		LOG_INF("Report Map parsed: len %u report_id %u%s",
			(unsigned int)ctx->hids.report_map_len, ctx->hids.mouse_parser.report_id,
			ctx->hids.mouse_parser.has_report_id ? "" : " (none)");

		ctx->hids.report_search_handle = ctx->hids.start_handle + 1U;
		memset(&ctx->hids.candidate, 0, sizeof(ctx->hids.candidate));
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
		return BT_GATT_ITER_STOP;
	}

	if ((ctx->hids.report_map_len + length) > sizeof(ctx->hids.report_map)) {
		LOG_WRN("Report Map too large: have %u incoming %u max %u",
			(unsigned int)ctx->hids.report_map_len, length,
			(unsigned int)sizeof(ctx->hids.report_map));
		hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED, "Report Map size", -EMSGSIZE);
		return BT_GATT_ITER_STOP;
	}

	(void)memcpy(&ctx->hids.report_map[ctx->hids.report_map_len], data, length);
	ctx->hids.report_map_len += length;

	return BT_GATT_ITER_CONTINUE;
}

static int hids_read_by_uuid(struct ble_hid_ctx *ctx, uint16_t uuid_value, uint16_t start_handle,
			     uint16_t end_handle, bt_gatt_read_func_t func)
{
	if (start_handle == 0U || start_handle > end_handle) {
		return -EINVAL;
	}

	memset(&ctx->read_params, 0, sizeof(ctx->read_params));
	ctx->read_params.func = func;
	/* Both the parameters and their UUID are owned by this asynchronous session. */
	ctx->read_uuid = (struct bt_uuid_16)BT_UUID_INIT_16(uuid_value);
	ctx->read_params.by_uuid.uuid = &ctx->read_uuid.uuid;
	ctx->read_params.by_uuid.start_handle = start_handle;
	ctx->read_params.by_uuid.end_handle = end_handle;
	return bt_gatt_read(ctx->conn, &ctx->read_params);
}

static void next_report_candidate(struct ble_hid_ctx *ctx, const char *reason)
{
	LOG_DBG("Skipping HID report 0x%04x: %s", ctx->hids.candidate.value_handle, reason);
	memset(&ctx->hids.candidate, 0, sizeof(ctx->hids.candidate));
	if (ctx->hids.report_search_handle == 0U) {
		hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED,
				      "no matching mouse Input Report", -ENOTSUP);
		return;
	}
	hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
}

static void report_candidate_range(struct ble_hid_ctx *ctx, uint16_t end_handle,
				   uint16_t next_handle)
{
	ctx->hids.candidate.end_handle = end_handle;
	ctx->hids.report_search_handle = next_handle;
	if (end_handle <= ctx->hids.candidate.value_handle) {
		next_report_candidate(ctx, "no descriptor range");
		return;
	}
	hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_REFERENCE);
}

static uint8_t report_characteristic_read_func(struct bt_conn *conn, uint8_t err,
					       struct bt_gatt_read_params *params, const void *data,
					       uint16_t length)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	struct hid_report_candidate *candidate = &ctx->hids.candidate;
	const uint8_t *declaration = data;
	struct bt_uuid_any uuid;
	uint16_t handle = params->by_uuid.start_handle;
	uint16_t value_handle;

	if (!conn_is_current(ctx, conn) || ctx->state != BLE_LINK_DISCOVERING ||
	    ctx->hids.discovery_step != HIDS_DISCOVERY_STEP_REPORT_CHAR) {
		return BT_GATT_ITER_STOP;
	}
	if (err && err != BT_ATT_ERR_ATTRIBUTE_NOT_FOUND) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "Report characteristic read", err);
		return BT_GATT_ITER_STOP;
	}
	if (err || data == NULL) {
		if (candidate->value_handle != 0U) {
			report_candidate_range(ctx, ctx->hids.end_handle, 0U);
		} else {
			ctx->hids.report_search_handle = 0U;
			next_report_candidate(ctx, "characteristic search complete");
		}
		return BT_GATT_ITER_STOP;
	}

	/* A characteristic declaration is properties, value handle, then a UUID. */
	if ((length != 5U && length != 19U) || handle < ctx->hids.report_search_handle ||
	    handle > ctx->hids.end_handle) {
		goto malformed;
	}
	value_handle = sys_get_le16(&declaration[1]);
	if (value_handle <= handle || value_handle > ctx->hids.end_handle ||
	    !bt_uuid_create(&uuid.uuid, &declaration[3], length - 3U)) {
		goto malformed;
	}
	if (candidate->value_handle != 0U) {
		if (handle <= candidate->value_handle) {
			goto malformed;
		}
		/* Every characteristic, not just another Report, bounds the descriptors. */
		report_candidate_range(ctx, handle - 1U, handle);
		return BT_GATT_ITER_STOP;
	}

	if (bt_uuid_cmp(&uuid.uuid, BT_UUID_HIDS_REPORT) == 0 &&
	    (declaration[0] & BT_GATT_CHRC_NOTIFY) != 0U) {
		candidate->value_handle = value_handle;
		candidate->properties = declaration[0];
	}
	return BT_GATT_ITER_CONTINUE;

malformed:
	hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "invalid characteristic declaration",
			      -EBADMSG);
	return BT_GATT_ITER_STOP;
}

static uint8_t report_descriptor_read_func(struct bt_conn *conn, uint8_t err,
					   struct bt_gatt_read_params *params, const void *data,
					   uint16_t length)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	struct hid_report_candidate *candidate = &ctx->hids.candidate;
	const uint8_t *reference = data;
	bool reading_reference = ctx->hids.discovery_step == HIDS_DISCOVERY_STEP_REPORT_REFERENCE;
	uint16_t handle = params->by_uuid.start_handle;
	uint8_t expected_id =
		ctx->hids.mouse_parser.has_report_id ? ctx->hids.mouse_parser.report_id : 0U;

	if (!conn_is_current(ctx, conn) || ctx->state != BLE_LINK_DISCOVERING ||
	    (!reading_reference && ctx->hids.discovery_step != HIDS_DISCOVERY_STEP_REPORT_CCC)) {
		return BT_GATT_ITER_STOP;
	}
	if (err && err != BT_ATT_ERR_ATTRIBUTE_NOT_FOUND) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "Report descriptor read", err);
		return BT_GATT_ITER_STOP;
	}
	if (err || data == NULL || length != 2U) {
		next_report_candidate(ctx, "descriptor missing or invalid length");
		return BT_GATT_ITER_STOP;
	}
	if (handle <= candidate->value_handle || handle > candidate->end_handle) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "descriptor outside characteristic",
				      -EBADMSG);
		return BT_GATT_ITER_STOP;
	}
	if (reading_reference) {
		if (reference[0] != expected_id || reference[1] != HID_REPORT_TYPE_INPUT) {
			next_report_candidate(ctx, "Report ID or type mismatch");
			return BT_GATT_ITER_STOP;
		}
		candidate->reference_handle = handle;
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CCC);
		return BT_GATT_ITER_STOP;
	}
	if (handle == candidate->reference_handle) {
		next_report_candidate(ctx, "descriptors share a handle");
		return BT_GATT_ITER_STOP;
	}

	candidate->ccc_handle = handle;
	/* Publish the subscription handles only after the complete candidate matches. */
	ctx->hids.report_handle = candidate->value_handle;
	ctx->hids.ccc_handle = candidate->ccc_handle;
	LOG_INF("Selected mouse Input Report ID %u, value 0x%04x, CCC 0x%04x", expected_id,
		ctx->hids.report_handle, ctx->hids.ccc_handle);
	hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_SUBSCRIBE_REPORT);
	return BT_GATT_ITER_STOP;
}

static uint8_t confirm_missing_func(struct bt_conn *conn, uint8_t err,
				    struct bt_gatt_read_params *params, const void *data,
				    uint16_t length)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	struct bt_uuid_any uuid;

	if (!conn_is_current(ctx, conn) || ctx->state != BLE_LINK_DISCOVERING ||
	    ctx->hids.discovery_step != HIDS_DISCOVERY_STEP_CONFIRM_MISSING) {
		return BT_GATT_ITER_STOP;
	}
	if (err && err != BT_ATT_ERR_ATTRIBUTE_NOT_FOUND) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "attribute confirmation", err);
		return BT_GATT_ITER_STOP;
	}
	if (err || data == NULL) {
		hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED,
				      "mandatory HID attribute absent", -ENOENT);
		return BT_GATT_ITER_STOP;
	}

	if (bt_uuid_cmp(params->by_uuid.uuid, BT_UUID_GATT_PRIMARY) == 0) {
		/* Service declarations contain service UUIDs, not report values. */
		if ((length != BT_UUID_SIZE_16 && length != BT_UUID_SIZE_128) ||
		    !bt_uuid_create(&uuid.uuid, data, length)) {
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "invalid service UUID",
					      -EBADMSG);
			return BT_GATT_ITER_STOP;
		}
		if (bt_uuid_cmp(&uuid.uuid, BT_UUID_HIDS) != 0) {
			return BT_GATT_ITER_CONTINUE;
		}
	}

	/* The attribute exists: the failed discovery was not proof of incompatibility. */
	hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "inconclusive discovery", -EAGAIN);
	return BT_GATT_ITER_STOP;
}

static void request_disconnect(struct ble_hid_ctx *ctx, uint8_t reason)
{
	if (ctx->conn == NULL || ctx->state == BLE_LINK_DISCONNECTING) {
		return;
	}

	ctx->disconnect_reason = reason;
	ctx->disconnect_attempts = 0U;
	set_state(ctx, BLE_LINK_DISCONNECTING);
	ctx->pending_discovery_step = HIDS_DISCOVERY_STEP_IDLE;
	(void)k_work_cancel_delayable(&ctx->hids_work);
	(void)k_work_reschedule(&ctx->disconnect_work, K_NO_WAIT);
}

static void disconnect_work_fn(struct k_work *work)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	struct bt_conn *conn;
	int err;

	ARG_UNUSED(work);
	if (ctx->state != BLE_LINK_DISCONNECTING || ctx->conn == NULL) {
		return;
	}

	/* Keep the object alive if the disconnect callback runs during the call. */
	conn = bt_conn_ref(ctx->conn);
	ctx->disconnect_attempts++;
	err = bt_conn_disconnect(conn, ctx->disconnect_reason);
	if (conn_is_current(ctx, conn) && ctx->state == BLE_LINK_DISCONNECTING) {
		if (err == -ENOTCONN) {
			release_peer(ctx, conn);
		} else if (err && ctx->disconnect_attempts < DISCONNECT_MAX_ATTEMPTS) {
			LOG_WRN("Disconnect failed (%d); retrying", err);
			(void)k_work_reschedule(&ctx->disconnect_work, DISCONNECT_RETRY_DELAY);
		} else if (err) {
			set_state(ctx, BLE_LINK_ERROR);
			(void)app_led_set_pattern(APP_LED_PATTERN_ON);
			LOG_ERR("Disconnect failed (%d). Press Button0 to retry, or reset the "
				"board if the controller is unresponsive",
				err);
		}
	}
	bt_conn_unref(conn);
}

static void hids_discovery_failed(struct ble_hid_ctx *ctx, enum hids_failure failure,
				  const char *what, int err)
{
	if (ctx->state != BLE_LINK_DISCOVERING) {
		return;
	}

	LOG_WRN("HIDS discovery failed: %s (%d), %s", what, err,
		failure == HIDS_FAILURE_UNSUPPORTED ? "unsupported peer" : "will retry");
	ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_IDLE;
	if (failure == HIDS_FAILURE_UNSUPPORTED && ctx->conn != NULL) {
		ctx->peer_compatibility = PEER_UNSUPPORTED;
		ctx->rejected_addr = *bt_conn_get_dst(ctx->conn);
		ctx->rejected_addr_valid = true;
	}
	request_disconnect(ctx, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

static void subscribe_func(struct bt_conn *conn, uint8_t err,
			   struct bt_gatt_subscribe_params *params)
{
	struct ble_hid_ctx *ctx = &ble_ctx;

	if (!conn_is_current(ctx, conn) || ctx->state != BLE_LINK_DISCOVERING ||
	    params != &ctx->subscribe_params) {
		return;
	}
	if (err) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "report CCC write", err);
		return;
	}

	ctx->hids_report_subscribed = true;
	hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_PROTOCOL_MODE);
}

static void hids_discovery_done(struct ble_hid_ctx *ctx)
{
	if (ctx->state != BLE_LINK_DISCOVERING || ctx->conn == NULL) {
		return;
	}

	if (!ctx->hids.mouse_parser.valid || !ctx->hids_report_subscribed) {
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "mouse not ready", -EAGAIN);
		return;
	}

	ctx->peer_compatibility = PEER_MOUSE;
	ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_DONE;
	set_state(ctx, BLE_LINK_READY);
	LOG_INF("HIDS mouse client ready");
	(void)app_led_set_pattern(APP_LED_PATTERN_OFF);
	if (ctx->conn != NULL && bt_le_bond_exists(BT_ID_DEFAULT, bt_conn_get_dst(ctx->conn))) {
		refresh_bond_state(ctx);
		set_pairing_mode_internal(ctx, false);
	}
}

static int hids_discovery_start(struct ble_hid_ctx *ctx, struct bt_conn *conn)
{
	if (!conn_is_current(ctx, conn)) {
		return -ENOTCONN;
	}

	if (ctx->state != BLE_LINK_CONNECTED) {
		return -EBUSY;
	}

	reset_hids_state(ctx);
	set_state(ctx, BLE_LINK_DISCOVERING);
	hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_SERVICE);

	return 0;
}

static void hids_schedule_step(struct ble_hid_ctx *ctx, enum hids_discovery_step step)
{
	if (ctx->state != BLE_LINK_DISCOVERING) {
		return;
	}

	ctx->pending_discovery_step = step;

	/*
	 * GATT callbacks run from the Bluetooth RX context. Do not reuse or clear
	 * discover_params, subscribe_params, or queue a new ATT procedure before
	 * the current callback has returned. The small delay guarantees that the
	 * next step runs from the system workqueue after Zephyr has released the
	 * previous params object.
	 */
	(void)k_work_reschedule(&ctx->hids_work, K_MSEC(1));
}

static void hids_work_fn(struct k_work *work)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	enum hids_discovery_step step;
	int err;

	ARG_UNUSED(work);

	if (ctx->state != BLE_LINK_DISCOVERING || ctx->conn == NULL) {
		return;
	}

	step = ctx->pending_discovery_step;
	ctx->pending_discovery_step = HIDS_DISCOVERY_STEP_IDLE;

	switch (step) {
	case HIDS_DISCOVERY_STEP_REPORT_CHAR:
	case HIDS_DISCOVERY_STEP_REPORT_REFERENCE:
	case HIDS_DISCOVERY_STEP_REPORT_CCC: {
		bool finding_report = step == HIDS_DISCOVERY_STEP_REPORT_CHAR;
		uint16_t uuid_value = finding_report ? BT_UUID_GATT_CHRC_VAL
						     : (step == HIDS_DISCOVERY_STEP_REPORT_REFERENCE
								? BT_UUID_HIDS_REPORT_REF_VAL
								: BT_UUID_GATT_CCC_VAL);
		uint16_t start_handle = finding_report ? ctx->hids.report_search_handle
						       : ctx->hids.candidate.value_handle + 1U;
		uint16_t end_handle =
			finding_report ? ctx->hids.end_handle : ctx->hids.candidate.end_handle;

		ctx->hids.discovery_step = step;
		err = hids_read_by_uuid(ctx, uuid_value, start_handle, end_handle,
					finding_report ? report_characteristic_read_func
						       : report_descriptor_read_func);
		if (err) {
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY,
					      "Report selection read start", err);
		}
		return;
	}

	case HIDS_DISCOVERY_STEP_CONFIRM_MISSING: {
		uint16_t uuid_value;
		bool service = ctx->hids.discovery_step == HIDS_DISCOVERY_STEP_SERVICE;

		switch (ctx->hids.discovery_step) {
		case HIDS_DISCOVERY_STEP_SERVICE:
			uuid_value = BT_UUID_GATT_PRIMARY_VAL;
			break;
		case HIDS_DISCOVERY_STEP_REPORT_MAP:
			uuid_value = BT_UUID_HIDS_REPORT_MAP_VAL;
			break;
		default:
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "invalid confirmation step",
					      -EINVAL);
			return;
		}
		ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_CONFIRM_MISSING;
		err = hids_read_by_uuid(
			ctx, uuid_value,
			service ? BT_ATT_FIRST_ATTRIBUTE_HANDLE : ctx->hids.start_handle + 1U,
			service ? BT_ATT_LAST_ATTRIBUTE_HANDLE : ctx->hids.end_handle,
			confirm_missing_func);
		if (err) {
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY,
					      "attribute confirmation start", err);
		}
		return;
	}

	case HIDS_DISCOVERY_STEP_READ_REPORT_MAP:
		if (ctx->hids.report_map_handle == 0U) {
			hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED, "Report Map missing",
					      -ENOENT);
			return;
		}

		(void)memset(&ctx->read_params, 0, sizeof(ctx->read_params));
		ctx->hids.report_map_len = 0U;
		ctx->read_params.func = report_map_read_func;
		ctx->read_params.handle_count = 1U;
		ctx->read_params.single.handle = ctx->hids.report_map_handle;
		ctx->read_params.single.offset = 0U;

		err = bt_gatt_read(ctx->conn, &ctx->read_params);
		if (err) {
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "Report Map read start",
					      err);
		}
		return;

	case HIDS_DISCOVERY_STEP_SUBSCRIBE_REPORT:
		if (ctx->hids.report_handle == 0U || ctx->hids.ccc_handle == 0U) {
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "no selected report",
					      -EINVAL);
			return;
		}
		/*
		 * subscribe_params is persistent and must not be reused for another
		 * subscription while active. The VOLATILE flag configured at init time
		 * makes Zephyr remove it on disconnect; here we only refresh fields that
		 * belong to the current connection before subscribing again.
		 */
		ctx->subscribe_params.notify = notify_func;
		ctx->subscribe_params.subscribe = subscribe_func;
		ctx->subscribe_params.value = BT_GATT_CCC_NOTIFY;
		ctx->subscribe_params.min_security = target_sec;
		ctx->subscribe_params.value_handle = ctx->hids.report_handle;
		ctx->subscribe_params.ccc_handle = ctx->hids.ccc_handle;

		atomic_set_bit(ctx->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
		atomic_set_bit(ctx->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_NO_RESUB);

		err = bt_gatt_subscribe(ctx->conn, &ctx->subscribe_params);
		if (err) {
			hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "report subscription", err);
		}
		/* Advance only after the peer acknowledges the CCC write. */

		return;

	case HIDS_DISCOVERY_STEP_WRITE_PROTOCOL_MODE: {
		uint8_t report_protocol = 0x01;

		if (ctx->hids.protocol_mode_handle != 0U) {
			err = bt_gatt_write_without_response(
				ctx->conn, ctx->hids.protocol_mode_handle, &report_protocol,
				sizeof(report_protocol), false);
			if (err) {
				LOG_WRN("Protocol Mode write failed: %d", err);
			}
		}

		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_CTRL_POINT);
		return;
	}

	case HIDS_DISCOVERY_STEP_WRITE_CTRL_POINT:
		if (ctx->hids.ctrl_point_handle != 0U) {
			(void)hids_ctrl_point_write(0x01);
		}
		hids_discovery_done(ctx);
		return;

	case HIDS_DISCOVERY_STEP_SERVICE:
	case HIDS_DISCOVERY_STEP_REPORT_MAP:
	case HIDS_DISCOVERY_STEP_PROTOCOL_MODE:
	case HIDS_DISCOVERY_STEP_CTRL_POINT:
		err = hids_discover_step(ctx, ctx->conn, step);
		if (err) {
			if (step == HIDS_DISCOVERY_STEP_PROTOCOL_MODE) {
				LOG_WRN("Protocol Mode discovery start failed: %d; continuing",
					err);
				hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_CTRL_POINT);
			} else if (step == HIDS_DISCOVERY_STEP_CTRL_POINT) {
				LOG_WRN("Control Point discovery start failed: %d; ready without "
					"it",
					err);
				hids_discovery_done(ctx);
			} else {
				hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "discovery start",
						      err);
			}
		}
		return;

	default:
		return;
	}
}

static int hids_discover_step(struct ble_hid_ctx *ctx, struct bt_conn *conn,
			      enum hids_discovery_step step)
{
	int err;

	if (!conn_is_current(ctx, conn)) {
		return -ENOTCONN;
	}

	(void)memset(&ctx->discover_params, 0, sizeof(ctx->discover_params));
	ctx->discover_params.func = discover_func;

	switch (step) {
	case HIDS_DISCOVERY_STEP_SERVICE:
		memcpy(&ctx->discover_uuid, BT_UUID_HIDS, sizeof(ctx->discover_uuid));
		ctx->discover_params.uuid = &ctx->discover_uuid.uuid;
		ctx->discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
		ctx->discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
		ctx->discover_params.type = BT_GATT_DISCOVER_PRIMARY;
		break;

	case HIDS_DISCOVERY_STEP_REPORT_MAP:
		memcpy(&ctx->discover_uuid, &report_map_uuid, sizeof(ctx->discover_uuid));
		ctx->discover_params.uuid = &ctx->discover_uuid.uuid;
		ctx->discover_params.start_handle = ctx->hids.start_handle + 1U;
		ctx->discover_params.end_handle = ctx->hids.end_handle;
		ctx->discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		break;

	case HIDS_DISCOVERY_STEP_PROTOCOL_MODE:
		memcpy(&ctx->discover_uuid, BT_UUID_HIDS_PROTOCOL_MODE, sizeof(ctx->discover_uuid));
		ctx->discover_params.uuid = &ctx->discover_uuid.uuid;
		ctx->discover_params.start_handle = ctx->hids.start_handle + 1U;
		ctx->discover_params.end_handle = ctx->hids.end_handle;
		ctx->discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		break;

	case HIDS_DISCOVERY_STEP_CTRL_POINT:
		memcpy(&ctx->discover_uuid, BT_UUID_HIDS_CTRL_POINT, sizeof(ctx->discover_uuid));
		ctx->discover_params.uuid = &ctx->discover_uuid.uuid;
		ctx->discover_params.start_handle = ctx->hids.start_handle + 1U;
		ctx->discover_params.end_handle = ctx->hids.end_handle;
		ctx->discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		break;

	default:
		return -EINVAL;
	}

	ctx->hids.discovery_step = step;
	LOG_DBG("Starting HIDS discovery step %d range 0x%04x-0x%04x", step,
		ctx->discover_params.start_handle, ctx->discover_params.end_handle);

	err = bt_gatt_discover(conn, &ctx->discover_params);
	if (err) {
		LOG_ERR("HIDS discovery step %d start failed: %d", step, err);
		ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_IDLE;
	}

	return err;
}

static uint8_t handle_discovery_not_found(struct ble_hid_ctx *ctx, struct bt_conn *conn,
					  struct bt_gatt_discover_params *params)
{
	enum hids_discovery_step step = ctx->hids.discovery_step;

	ARG_UNUSED(conn);
	ARG_UNUSED(params);

	switch (step) {
	case HIDS_DISCOVERY_STEP_SERVICE:
	case HIDS_DISCOVERY_STEP_REPORT_MAP:
		/* Discovery hides ATT errors; confirm absence with an error-reporting read. */
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_CONFIRM_MISSING);
		break;

	case HIDS_DISCOVERY_STEP_PROTOCOL_MODE:
		LOG_INF("HID Protocol Mode characteristic not found; continuing");
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_CTRL_POINT);
		break;

	case HIDS_DISCOVERY_STEP_CTRL_POINT:
		LOG_INF("HID Control Point characteristic not found; ready without it");
		hids_discovery_done(ctx);
		break;

	default:
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "unexpected discovery result",
				      -EINVAL);
		break;
	}

	return BT_GATT_ITER_STOP;
}

static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	struct ble_hid_ctx *ctx = &ble_ctx;

	if (!conn_is_current(ctx, conn) || ctx->state != BLE_LINK_DISCOVERING) {
		return BT_GATT_ITER_STOP;
	}

	if (attr == NULL) {
		return handle_discovery_not_found(ctx, conn, params);
	}

	switch (ctx->hids.discovery_step) {
	case HIDS_DISCOVERY_STEP_SERVICE: {
		const struct bt_gatt_service_val *svc = attr->user_data;

		if (svc == NULL || attr->handle == 0U || svc->end_handle <= attr->handle) {
			hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED, "HID service handles",
					      -EBADMSG);
			return BT_GATT_ITER_STOP;
		}

		ctx->hids.start_handle = attr->handle;
		ctx->hids.end_handle = svc->end_handle;
		LOG_DBG("HID service: start 0x%04x end 0x%04x", ctx->hids.start_handle,
			ctx->hids.end_handle);

		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_MAP);
		return BT_GATT_ITER_STOP;
	}

	case HIDS_DISCOVERY_STEP_REPORT_MAP: {
		const struct bt_gatt_chrc *chrc = attr->user_data;

		if (chrc == NULL || chrc->value_handle == 0U) {
			hids_discovery_failed(ctx, HIDS_FAILURE_UNSUPPORTED,
					      "HID Report Map handle", -EBADMSG);
			return BT_GATT_ITER_STOP;
		}

		ctx->hids.report_map_handle = chrc->value_handle;
		LOG_DBG("HID Report Map characteristic: decl 0x%04x value 0x%04x", attr->handle,
			ctx->hids.report_map_handle);

		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_READ_REPORT_MAP);
		return BT_GATT_ITER_STOP;
	}

	case HIDS_DISCOVERY_STEP_PROTOCOL_MODE: {
		const struct bt_gatt_chrc *chrc = attr->user_data;

		if (chrc == NULL || chrc->value_handle == 0U) {
			LOG_WRN("HID Protocol Mode characteristic has no value handle; continuing");
			hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_CTRL_POINT);
			return BT_GATT_ITER_STOP;
		}

		ctx->hids.protocol_mode_handle = chrc->value_handle;
		LOG_DBG("HID Protocol Mode characteristic: decl 0x%04x value 0x%04x", attr->handle,
			ctx->hids.protocol_mode_handle);
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_WRITE_PROTOCOL_MODE);
		return BT_GATT_ITER_STOP;
	}

	case HIDS_DISCOVERY_STEP_CTRL_POINT: {
		const struct bt_gatt_chrc *chrc = attr->user_data;

		if (chrc == NULL || chrc->value_handle == 0U) {
			LOG_WRN("HID Control Point characteristic has no value handle; ready "
				"without it");
			hids_discovery_done(ctx);
			return BT_GATT_ITER_STOP;
		}

		ctx->hids.ctrl_point_handle = chrc->value_handle;
		LOG_DBG("HID Control Point characteristic: decl 0x%04x value 0x%04x", attr->handle,
			ctx->hids.ctrl_point_handle);
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_WRITE_CTRL_POINT);
		return BT_GATT_ITER_STOP;
	}

	default:
		hids_discovery_failed(ctx, HIDS_FAILURE_RETRY, "unexpected discovery step",
				      -EINVAL);
		return BT_GATT_ITER_STOP;
	}
}

static void connected(struct bt_conn *conn, uint8_t conn_err)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	char addr[BT_ADDR_LE_STR_LEN];
	int err;

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!conn_is_current(ctx, conn)) {
		return;
	}

	if (conn_err) {
		LOG_WRN("Failed to connect to %s: 0x%02x", addr, conn_err);
		bt_conn_unref(ctx->conn);
		ctx->conn = NULL;
		set_state(ctx, BLE_LINK_IDLE);
		schedule_reconnect(ctx);
		return;
	}
	if (ctx->state == BLE_LINK_DISCONNECTING) {
		/* A successful connection can race with cancellation of its initiation. */
		(void)k_work_reschedule(&ctx->disconnect_work, K_NO_WAIT);
		return;
	}
	if (ctx->state == BLE_LINK_ERROR) {
		return;
	}
	if (ctx->forget_pending) {
		request_disconnect(ctx, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return;
	}

	/* Old mouse events and held-button state do not belong to the new link. */
	app_input_reset_mouse();
	LOG_INF("Connected: %s", addr);
	set_state(ctx, BLE_LINK_CONNECTED);

	err = bt_conn_set_security(conn, target_sec);
	if (err) {
		LOG_WRN("bt_conn_set_security(%u) failed: %d", target_sec, err);
		err = hids_discovery_start(ctx, conn);
		if (err) {
			LOG_ERR("HIDS discovery could not start without security: %d", err);
		}
	}
}

static void release_peer(struct ble_hid_ctx *ctx, struct bt_conn *conn)
{
	bt_addr_le_t peer_addr = *bt_conn_get_dst(conn);
	int err;

	if (!conn_is_current(ctx, conn)) {
		return;
	}

	(void)k_work_cancel_delayable(&ctx->hids_work);
	(void)k_work_cancel_delayable(&ctx->disconnect_work);
	bt_gatt_cancel(conn, &ctx->discover_params);
	bt_gatt_cancel(conn, &ctx->read_params);

	bt_conn_unref(ctx->conn);
	ctx->conn = NULL;
	if (ctx->peer_compatibility == PEER_UNSUPPORTED && !ctx->forget_pending) {
		/* Bond age is irrelevant: every connection is checked for compatibility. */
		err = bt_unpair(BT_ID_DEFAULT, &peer_addr);
		if (err) {
			LOG_WRN("Failed to remove unsupported peer bond: %d", err);
		}
	}
	ctx->peer_compatibility = PEER_UNVERIFIED;

	reset_hids_state(ctx);
	set_state(ctx, BLE_LINK_IDLE);

	refresh_bond_state(ctx);
	if (ctx->forget_pending) {
		(void)app_led_set_pattern(APP_LED_PATTERN_ON);
	} else {
		(void)app_led_set_pattern(ctx->pairing_mode ? APP_LED_PATTERN_BLINK_FAST
							    : APP_LED_PATTERN_BLINK_SLOW);
	}
	schedule_reconnect(ctx);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Disconnected: %s reason 0x%02x %s", addr, reason, bt_hci_err_to_str(reason));
	release_peer(&ble_ctx, conn);
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	char addr[BT_ADDR_LE_STR_LEN];
	int rc;

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (!conn_is_current(ctx, conn)) {
		return;
	}

	if (err) {
		LOG_WRN("Security failed: %s level %u err %d", addr, level, err);
		request_disconnect(ctx, BT_HCI_ERR_AUTH_FAIL);
		return;
	}

	LOG_INF("Security changed: %s level %u", addr, level);

	if (level < target_sec || ctx->state != BLE_LINK_CONNECTED) {
		return;
	}

	rc = hids_discovery_start(ctx, conn);
	if (rc) {
		LOG_ERR("HIDS discovery start failed: %d", rc);
	}
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
};

static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Pairing cancelled: %s", addr);
}

static void auth_pairing_confirm(struct bt_conn *conn)
{
	if (!ble_ctx.pairing_mode) {
		LOG_INF("Pairing rejected: pairing mode disabled");
		bt_conn_auth_cancel(conn);
		return;
	}

	LOG_INF("Pairing accepted");
	bt_conn_auth_pairing_confirm(conn);
}

static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Passkey for %s: %06u", addr, passkey);
}

static void auth_passkey_confirm(struct bt_conn *conn, unsigned int passkey)
{
	if (!ble_ctx.pairing_mode) {
		LOG_INF("Numeric comparison rejected: pairing mode disabled");
		bt_conn_auth_cancel(conn);
		return;
	}
	LOG_INF("Numeric comparison: %06u; accepting", passkey);
	bt_conn_auth_passkey_confirm(conn);
}

static void auth_passkey_entry(struct bt_conn *conn)
{
	ARG_UNUSED(conn);

	LOG_INF("Passkey entry requested but not supported; cancelling pairing");
	bt_conn_auth_cancel(conn);
}

static struct bt_conn_auth_cb auth_cb = {
	.passkey_display = auth_passkey_display,
	.passkey_confirm = auth_passkey_confirm,
	.passkey_entry = auth_passkey_entry,
	.pairing_confirm = auth_pairing_confirm,
	.cancel = auth_cancel,
};

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Pairing complete: %s bonded=%u", addr, bonded);
	if (!conn_is_current(&ble_ctx, conn)) {
		return;
	}

	if (bonded) {
		refresh_bond_state(&ble_ctx);
		/* Encryption/bonding alone does not establish mouse compatibility. */
		if (ble_ctx.peer_compatibility == PEER_MOUSE) {
			set_pairing_mode_internal(&ble_ctx, false);
		}
	}
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_WRN("Pairing failed: %s reason=%d", addr, reason);
	if (conn_is_current(&ble_ctx, conn)) {
		request_disconnect(&ble_ctx, BT_HCI_ERR_AUTH_FAIL);
	}
}

static struct bt_conn_auth_info_cb auth_info_cb = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
};

static int hids_ctrl_point_write(uint8_t val)
{
	struct ble_hid_ctx *ctx = &ble_ctx;

	if (ctx->conn == NULL) {
		return -ENOTCONN;
	}

	if (ctx->hids.ctrl_point_handle == 0U) {
		return -EINVAL;
	}

	return bt_gatt_write_without_response(ctx->conn, ctx->hids.ctrl_point_handle, &val,
					      sizeof(val), false);
}

static void pairing_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (!ble_ctx.pairing_mode) {
		return;
	}

	LOG_INF("Pairing mode timeout");
	set_pairing_mode_internal(&ble_ctx, false);
}

static void pairing_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	request_forget_and_pair(&ble_ctx);
}

static void request_forget_and_pair(struct ble_hid_ctx *ctx)
{
	ctx->forget_pending = true;
	ctx->pairing_mode = false;
	if (ctx->state == BLE_LINK_DISABLED || ctx->state == BLE_LINK_ENABLING) {
		return;
	}

	LOG_INF("Forgetting the mouse and starting fresh pairing");
	(void)app_led_set_pattern(APP_LED_PATTERN_ON);
	(void)k_work_cancel_delayable(&ctx->pairing_timeout_work);
	(void)k_work_cancel_delayable(&ctx->reconnect_work);
	stop_scan(ctx);
	if (ctx->conn != NULL) {
		request_disconnect(ctx, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	} else if (ctx->state != BLE_LINK_CONNECTING) {
		(void)k_work_submit(&forget_work);
	}
	/* An in-flight create attempt resumes this operation when it stops. */
}

static void begin_pairing_window(struct ble_hid_ctx *ctx)
{
	ctx->rejected_addr_valid = false;
	ctx->scan_start_attempts = 0U;

	(void)app_led_set_pattern(APP_LED_PATTERN_BLINK_FAST);
	(void)k_work_cancel_delayable(&ctx->reconnect_work);
	(void)k_work_reschedule(&ctx->pairing_timeout_work, PAIRING_MODE_TIMEOUT);
	start_scan(ctx);
}

static void forget_work_fn(struct k_work *work)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	int err = 0;

	ARG_UNUSED(work);
	if (!ctx->forget_pending || ctx->conn != NULL ||
	    (ctx->state != BLE_LINK_IDLE && ctx->state != BLE_LINK_ERROR)) {
		return;
	}

	/* Only this worker clears the bond for an explicit forget request. */
	refresh_bond_state(ctx);
	if (ctx->bonded_addr_valid) {
		err = bt_unpair(BT_ID_DEFAULT, &ctx->bonded_addr);
	}
	if (err) {
		set_state(ctx, BLE_LINK_ERROR);
		(void)app_led_set_pattern(APP_LED_PATTERN_ON);
		LOG_ERR("Failed to forget mouse bond (%d). Press Button0 to retry", err);
		return;
	}

	refresh_bond_state(ctx);
	ctx->forget_pending = false;
	set_state(ctx, BLE_LINK_IDLE);
	/* There is no old bond to exclude; the same mouse can pair again. */
	set_pairing_mode_internal(ctx, true);
}

static void set_pairing_mode_internal(struct ble_hid_ctx *ctx, bool enable)
{
	if (ctx->forget_pending) {
		return;
	}
	if (ctx->pairing_mode == enable) {
		return;
	}

	ctx->pairing_mode = enable;
	LOG_INF("Pairing mode %s", enable ? "enabled" : "disabled");
	if (ctx->state == BLE_LINK_DISABLED || ctx->state == BLE_LINK_ENABLING) {
		return;
	}
	if (enable) {
		begin_pairing_window(ctx);
		return;
	}

	(void)k_work_cancel_delayable(&ctx->pairing_timeout_work);

	if (!ctx->bonded_addr_valid) {
		(void)k_work_cancel_delayable(&ctx->reconnect_work);
		if (ctx->state == BLE_LINK_SCANNING) {
			stop_scan(ctx);
		}
	}
	if (ctx->conn == NULL && ctx->state == BLE_LINK_IDLE) {
		/* A newly bonded peer may still need validation after a transient error. */
		schedule_reconnect(ctx);
	}

	if (ctx->conn != NULL && ctx->peer_compatibility != PEER_MOUSE &&
	    ctx->state != BLE_LINK_ERROR) {
		request_disconnect(ctx, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}

	if (ctx->state == BLE_LINK_ERROR) {
		(void)app_led_set_pattern(APP_LED_PATTERN_ON);
	} else if (ctx->bonded_addr_valid && ctx->state != BLE_LINK_READY) {
		(void)app_led_set_pattern(APP_LED_PATTERN_BLINK_SLOW);
	} else {
		(void)app_led_set_pattern(APP_LED_PATTERN_OFF);
	}
}

static void bt_ready_cb(int err)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	int rc;

	if (err) {
		LOG_ERR("Bluetooth init failed: %d", err);
		set_state(ctx, BLE_LINK_DISABLED);
		return;
	}

	rc = settings_load();
	if (rc) {
		LOG_WRN("settings_load failed: %d", rc);
	}

	rc = bt_conn_auth_cb_register(&auth_cb);
	if (rc) {
		LOG_WRN("bt_conn_auth_cb_register failed: %d", rc);
	}

	rc = bt_conn_auth_info_cb_register(&auth_info_cb);
	if (rc) {
		LOG_WRN("bt_conn_auth_info_cb_register failed: %d", rc);
	}

	refresh_bond_state(ctx);
	set_state(ctx, BLE_LINK_IDLE);

	LOG_INF("Bluetooth initialized");
	if (ctx->forget_pending) {
		request_forget_and_pair(ctx);
	} else {
		(void)app_led_set_pattern(APP_LED_PATTERN_BLINK_SLOW);
		if (ctx->bonded_addr_valid) {
			schedule_reconnect(ctx);
		} else {
			LOG_INF("No bond. Press Button0 to enable pairing mode.");
		}
	}
}

static int bt_connection_enable(void)
{
	int err;
	struct ble_hid_ctx *ctx = &ble_ctx;

	if (ctx->state != BLE_LINK_DISABLED) {
		return -EALREADY;
	}

	k_work_init_delayable(&ctx->pairing_timeout_work, pairing_timeout_fn);
	k_work_init_delayable(&ctx->reconnect_work, reconnect_work_fn);
	k_work_init_delayable(&ctx->hids_work, hids_work_fn);
	k_work_init_delayable(&ctx->disconnect_work, disconnect_work_fn);
	init_subscribe_params(ctx);

	set_state(ctx, BLE_LINK_ENABLING);

	err = bt_enable(bt_ready_cb);
	if (err) {
		LOG_ERR("bt_enable failed: %d", err);
		set_state(ctx, BLE_LINK_DISABLED);
	}

	return err;
}

int ble_hid_app_start(void)
{
	int err;

	err = app_led_init();
	if (err) {
		LOG_ERR("LED initialization failed: %d", err);
		return err;
	}

	return bt_connection_enable();
}

static void button_input_cb(struct input_event *evt, void *user_data)
{
	ARG_UNUSED(user_data);

	if (evt->sync == 0) {
		return;
	}

	if (evt->code != INPUT_KEY_0) {
		return;
	}

	LOG_INF("Button %d %s at %" PRIu32, evt->code, evt->value ? "pressed" : "released",
		k_cycle_get_32());

	if (evt->value) {
		(void)k_work_submit(&pairing_work);
	}
}

INPUT_CALLBACK_DEFINE(NULL, button_input_cb, NULL);
