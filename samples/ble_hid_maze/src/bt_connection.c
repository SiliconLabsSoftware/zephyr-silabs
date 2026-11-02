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
#include <zephyr/types.h>

#include <zephyr/dt-bindings/input/input-event-codes.h>

#include "app_input.h"
#include "app_led.h"
#include "app_types.h"
#include "ble_hid_app.h"
#include "hid_mouse.h"

LOG_MODULE_REGISTER(bt_connection, LOG_LEVEL_INF);

/* Only connect to very near devices when pairing openly. */
#define RSSI_CONNECT_THRESHOLD  (-30)
#define PAIRING_MODE_TIMEOUT    K_SECONDS(60)
#define RECONNECT_DELAY         K_MSEC(1500)
#define HIDS_REPORT_MAP_MAX_LEN 512U

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
};

enum hids_discovery_step {
	HIDS_DISCOVERY_STEP_IDLE,
	HIDS_DISCOVERY_STEP_SERVICE,
	HIDS_DISCOVERY_STEP_REPORT_MAP,
	HIDS_DISCOVERY_STEP_READ_REPORT_MAP,
	HIDS_DISCOVERY_STEP_REPORT_CHAR,
	HIDS_DISCOVERY_STEP_REPORT_CCC,
	HIDS_DISCOVERY_STEP_SUBSCRIBE_REPORT,
	HIDS_DISCOVERY_STEP_PROTOCOL_MODE,
	HIDS_DISCOVERY_STEP_WRITE_PROTOCOL_MODE,
	HIDS_DISCOVERY_STEP_CTRL_POINT,
	HIDS_DISCOVERY_STEP_WRITE_CTRL_POINT,
	HIDS_DISCOVERY_STEP_DONE,
};

struct hids_client_state {
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t report_map_handle;
	uint16_t report_handle;
	uint16_t ccc_handle;
	uint16_t protocol_mode_handle;
	uint16_t ctrl_point_handle;
	enum hids_discovery_step discovery_step;
	struct hid_mouse_parser mouse_parser;
	uint8_t report_map[HIDS_REPORT_MAP_MAX_LEN];
	size_t report_map_len;
};

struct ble_hid_ctx {
	struct bt_conn *conn;
	enum ble_link_state state;

	bool pairing_mode;
	bool bonded_addr_valid;
	bt_addr_le_t bonded_addr;

	struct bt_uuid_16 discover_uuid;
	struct bt_gatt_discover_params discover_params;
	struct bt_gatt_read_params read_params;
	struct bt_gatt_subscribe_params subscribe_params;
	struct hids_client_state hids;
	enum hids_discovery_step pending_discovery_step;
	bool hids_report_subscribed;

	struct k_work_delayable pairing_timeout_work;
	struct k_work_delayable reconnect_work;
	struct k_work_delayable hids_work;
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
static void pairing_toggle_work_fn(struct k_work *work);
static void hids_schedule_step(struct ble_hid_ctx *ctx, enum hids_discovery_step step);

K_WORK_DEFINE(pairing_toggle_work, pairing_toggle_work_fn);

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
	if (ctx->bonded_addr_valid && !ctx->pairing_mode) {
		return bt_addr_le_cmp(addr, &ctx->bonded_addr) == 0;
	}

	return ctx->pairing_mode;
}

static bool should_connect_to_device(const struct ble_hid_ctx *ctx, const bt_addr_le_t *addr,
				     int8_t rssi, uint8_t adv_type)
{
	if (ctx->state != BLE_LINK_SCANNING) {
		return false;
	}

	if (ctx->conn != NULL) {
		return false;
	}

	if (!adv_type_is_connectable(adv_type)) {
		return false;
	}

	/* Proximity filtering is only needed while accepting a new peer. */
	if (ctx->pairing_mode && rssi < RSSI_CONNECT_THRESHOLD) {
		return false;
	}

	return peer_allowed(ctx, addr);
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

	ARG_UNUSED(ad);

	if (!should_connect_to_device(ctx, addr, rssi, type)) {
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

	if (ctx->conn != NULL || ctx->state == BLE_LINK_CONNECTING ||
	    ctx->state == BLE_LINK_CONNECTED || ctx->state == BLE_LINK_DISCOVERING ||
	    ctx->state == BLE_LINK_READY || ctx->state == BLE_LINK_SCANNING) {
		return;
	}

	if (!ctx->bonded_addr_valid && !ctx->pairing_mode) {
		LOG_INF("Scan not started: no bond and pairing mode is disabled");
		return;
	}

	err = bt_le_scan_start(&scan_param, device_found);
	if (err == -EALREADY) {
		set_state(ctx, BLE_LINK_SCANNING);
		return;
	}

	if (err) {
		LOG_ERR("Scan start failed: %d", err);
		set_state(ctx, BLE_LINK_IDLE);
		return;
	}

	set_state(ctx, BLE_LINK_SCANNING);
	LOG_INF("Scanning started");
}

static void schedule_reconnect(struct ble_hid_ctx *ctx)
{
	if (ctx->state != BLE_LINK_IDLE) {
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

	/* Give the controller a short gap between scan stop and initiate. */
	k_sleep(K_MSEC(100));

	set_state(ctx, BLE_LINK_CONNECTING);

	LOG_INF("Creating HID connection using 1M PHY");
	err = connect_with_params(ctx, addr, &create_param_1m);
	if (!err) {
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

	ARG_UNUSED(conn);

	if (data == NULL) {
		LOG_INF("HID notifications unsubscribed");
		ble_ctx.hids_report_subscribed = false;
		return BT_GATT_ITER_STOP;
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

	if (!conn_is_current(ctx, conn)) {
		return BT_GATT_ITER_STOP;
	}

	if (err) {
		LOG_WRN("Report Map read failed: 0x%02x; mouse reports will be ignored", err);
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
		return BT_GATT_ITER_STOP;
	}

	if (data == NULL) {

		LOG_INF("Report Map length: %u", ctx->hids.report_map_len);

		LOG_HEXDUMP_DBG(ctx->hids.report_map, ctx->hids.report_map_len, "HID Report Map");

		rc = hid_mouse_parser_init(&ctx->hids.mouse_parser, ctx->hids.report_map,
					   ctx->hids.report_map_len);
		if (rc) {
			LOG_WRN("Report Map parse failed: %d; mouse reports will be ignored", rc);
		} else {
			LOG_INF("Report Map parsed: len %u report_id %u%s",
				(unsigned int)ctx->hids.report_map_len,
				ctx->hids.mouse_parser.report_id,
				ctx->hids.mouse_parser.has_report_id ? "" : " (none)");
		}

		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
		return BT_GATT_ITER_STOP;
	}

	if ((ctx->hids.report_map_len + length) > sizeof(ctx->hids.report_map)) {
		LOG_WRN("Report Map too large: have %u incoming %u max %u",
			(unsigned int)ctx->hids.report_map_len, length,
			(unsigned int)sizeof(ctx->hids.report_map));
		ctx->hids.report_map_len = 0U;
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
		return BT_GATT_ITER_STOP;
	}

	(void)memcpy(&ctx->hids.report_map[ctx->hids.report_map_len], data, length);
	ctx->hids.report_map_len += length;

	return BT_GATT_ITER_CONTINUE;
}

static void hids_discovery_failed(struct ble_hid_ctx *ctx, const char *what)
{
	LOG_ERR("HIDS discovery failed: %s", what);
	ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_IDLE;

	if (ctx->conn != NULL) {
		set_state(ctx, BLE_LINK_CONNECTED);
	} else {
		set_state(ctx, BLE_LINK_IDLE);
	}
}

static void hids_discovery_done(struct ble_hid_ctx *ctx)
{
	ctx->hids.discovery_step = HIDS_DISCOVERY_STEP_DONE;
	set_state(ctx, BLE_LINK_READY);
	LOG_INF("HIDS client ready%s", ctx->hids.mouse_parser.valid
					       ? " with parsed Report Map"
					       : " without a usable Report Map");
	app_led_off();
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
	case HIDS_DISCOVERY_STEP_READ_REPORT_MAP:
		if (ctx->hids.report_map_handle == 0U) {
			LOG_WRN("Report Map handle missing; mouse reports will be ignored");
			hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
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
			LOG_WRN("Report Map read start failed: %d; mouse reports will be ignored",
				err);
			hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
		}
		return;

	case HIDS_DISCOVERY_STEP_SUBSCRIBE_REPORT:
		/*
		 * subscribe_params is persistent and must not be reused for another
		 * subscription while active. The VOLATILE flag configured at init time
		 * makes Zephyr remove it on disconnect; here we only refresh fields that
		 * belong to the current connection before subscribing again.
		 */
		ctx->subscribe_params.notify = notify_func;
		ctx->subscribe_params.value = BT_GATT_CCC_NOTIFY;
		ctx->subscribe_params.min_security = target_sec;
		ctx->subscribe_params.value_handle = ctx->hids.report_handle;
		ctx->subscribe_params.ccc_handle = ctx->hids.ccc_handle;

		atomic_set_bit(ctx->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
		atomic_set_bit(ctx->subscribe_params.flags, BT_GATT_SUBSCRIBE_FLAG_NO_RESUB);

		err = bt_gatt_subscribe(ctx->conn, &ctx->subscribe_params);
		if (err == -EALREADY) {
			LOG_WRN("HID report subscription already active; continuing");
			ctx->hids_report_subscribed = true;
			hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_PROTOCOL_MODE);
		} else if (err) {
			LOG_ERR("HID report subscribe failed: %d", err);
			hids_discovery_failed(ctx, "report subscription");
		} else {
			ctx->hids_report_subscribed = true;
			LOG_INF("HID report notifications subscribed");
			hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_PROTOCOL_MODE);
		}

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
	case HIDS_DISCOVERY_STEP_REPORT_CHAR:
	case HIDS_DISCOVERY_STEP_REPORT_CCC:
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
				hids_discovery_failed(ctx, "discovery start");
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

	case HIDS_DISCOVERY_STEP_REPORT_CHAR:
		memcpy(&ctx->discover_uuid, BT_UUID_HIDS_REPORT, sizeof(ctx->discover_uuid));
		ctx->discover_params.uuid = &ctx->discover_uuid.uuid;
		ctx->discover_params.start_handle = ctx->hids.start_handle + 1U;
		ctx->discover_params.end_handle = ctx->hids.end_handle;
		ctx->discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		break;

	case HIDS_DISCOVERY_STEP_REPORT_CCC:
		memcpy(&ctx->discover_uuid, BT_UUID_GATT_CCC, sizeof(ctx->discover_uuid));
		ctx->discover_params.uuid = &ctx->discover_uuid.uuid;
		ctx->discover_params.start_handle = ctx->hids.report_handle + 1U;
		ctx->discover_params.end_handle = ctx->hids.end_handle;
		ctx->discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
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
		hids_discovery_failed(ctx, "HID service not found");
		break;

	case HIDS_DISCOVERY_STEP_REPORT_MAP:
		LOG_WRN("HID Report Map characteristic not found; mouse reports will be ignored");
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
		break;

	case HIDS_DISCOVERY_STEP_REPORT_CHAR:
		hids_discovery_failed(ctx, "HID report characteristic not found");
		break;

	case HIDS_DISCOVERY_STEP_REPORT_CCC:
		hids_discovery_failed(ctx, "HID report CCC not found");
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
		hids_discovery_failed(ctx, "unexpected empty discovery result");
		break;
	}

	return BT_GATT_ITER_STOP;
}

static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	struct ble_hid_ctx *ctx = &ble_ctx;

	if (!conn_is_current(ctx, conn)) {
		return BT_GATT_ITER_STOP;
	}

	if (attr == NULL) {
		return handle_discovery_not_found(ctx, conn, params);
	}

	switch (ctx->hids.discovery_step) {
	case HIDS_DISCOVERY_STEP_SERVICE: {
		const struct bt_gatt_service_val *svc = attr->user_data;

		if (svc == NULL || svc->end_handle == 0U) {
			hids_discovery_failed(ctx, "HID service has invalid handle range");
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
			LOG_WRN("HID Report Map characteristic has no value handle; mouse reports "
				"will be ignored");
			hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CHAR);
			return BT_GATT_ITER_STOP;
		}

		ctx->hids.report_map_handle = chrc->value_handle;
		LOG_DBG("HID Report Map characteristic: decl 0x%04x value 0x%04x", attr->handle,
			ctx->hids.report_map_handle);

		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_READ_REPORT_MAP);
		return BT_GATT_ITER_STOP;
	}

	case HIDS_DISCOVERY_STEP_REPORT_CHAR: {
		const struct bt_gatt_chrc *chrc = attr->user_data;

		if (chrc == NULL || chrc->value_handle == 0U) {
			hids_discovery_failed(ctx, "HID report characteristic has no value handle");
			return BT_GATT_ITER_STOP;
		}

		ctx->hids.report_handle = chrc->value_handle;
		LOG_DBG("HID report characteristic: decl 0x%04x value 0x%04x", attr->handle,
			ctx->hids.report_handle);
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_REPORT_CCC);
		return BT_GATT_ITER_STOP;
	}

	case HIDS_DISCOVERY_STEP_REPORT_CCC:
		if (bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CCC)) {
			return BT_GATT_ITER_CONTINUE;
		}

		ctx->hids.ccc_handle = attr->handle;
		LOG_DBG("HID report CCC: handle 0x%04x", ctx->hids.ccc_handle);
		hids_schedule_step(ctx, HIDS_DISCOVERY_STEP_SUBSCRIBE_REPORT);
		return BT_GATT_ITER_STOP;

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
		hids_discovery_failed(ctx, "unexpected discovery step");
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

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	struct ble_hid_ctx *ctx = &ble_ctx;
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("Disconnected: %s reason 0x%02x %s", addr, reason, bt_hci_err_to_str(reason));
	app_led_blink_slow();
	if (!conn_is_current(ctx, conn)) {
		return;
	}

	if (ctx->state == BLE_LINK_DISCOVERING) {
		(void)k_work_cancel_delayable(&ctx->hids_work);
		bt_gatt_cancel(conn, &ctx->discover_params);
	}

	bt_conn_unref(ctx->conn);
	ctx->conn = NULL;

	reset_hids_state(ctx);
	set_state(ctx, BLE_LINK_IDLE);

	refresh_bond_state(ctx);
	schedule_reconnect(ctx);
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
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
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

	if (bonded) {
		refresh_bond_state(&ble_ctx);
		set_pairing_mode_internal(&ble_ctx, false);
	}
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_WRN("Pairing failed: %s reason=%d", addr, reason);
	(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
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

static void pairing_toggle_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	set_pairing_mode_internal(&ble_ctx, !ble_ctx.pairing_mode);
}

static void set_pairing_mode_internal(struct ble_hid_ctx *ctx, bool enable)
{
	if (ctx->pairing_mode == enable) {
		return;
	}

	ctx->pairing_mode = enable;
	LOG_INF("Pairing mode %s", enable ? "enabled" : "disabled");
	if (enable) {
		app_led_blink_fast();
	} else {
		app_led_off();
	}

	if (ctx->state == BLE_LINK_DISABLED || ctx->state == BLE_LINK_ENABLING) {
		return;
	}

	if (enable) {
		(void)k_work_schedule(&ctx->pairing_timeout_work, PAIRING_MODE_TIMEOUT);

		if (ctx->state == BLE_LINK_IDLE) {
			start_scan(ctx);
		}
		return;
	}

	(void)k_work_cancel_delayable(&ctx->pairing_timeout_work);

	if (!ctx->bonded_addr_valid && ctx->state == BLE_LINK_SCANNING) {
		stop_scan(ctx);
	}

	if (!ctx->bonded_addr_valid && ctx->conn != NULL) {
		LOG_INF("Disconnecting unbonded peer after pairing mode was disabled");
		(void)bt_conn_disconnect(ctx->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
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
	app_led_blink_slow();

	if (ctx->pairing_mode) {
		(void)k_work_schedule(&ctx->pairing_timeout_work, PAIRING_MODE_TIMEOUT);
		start_scan(ctx);
	} else if (ctx->bonded_addr_valid) {
		schedule_reconnect(ctx);
	} else {
		LOG_INF("No bond. Press Button0 to enable pairing mode.");
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
		(void)k_work_submit(&pairing_toggle_work);
	}
}

INPUT_CALLBACK_DEFINE(NULL, button_input_cb, NULL);
