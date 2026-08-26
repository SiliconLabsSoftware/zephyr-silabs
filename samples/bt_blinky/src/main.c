/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/devicetree.h>

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/spinlock.h>
#include <zephyr/drivers/gpio.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/services/bas.h>

/* The devicetree node identifier for the "led0" alias. */
#define LED0_NODE DT_ALIAS(led0)
#define BTN0_NODE DT_ALIAS(sw0)

/* Time interval for battery level notification */
#define BAT_NOT K_MSEC(1000)

static struct k_spinlock lock;
struct k_poll_signal signal;
static struct k_work_delayable bat_work;
static struct bt_conn *current_conn;

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID16_ALL,
				  BT_UUID_16_ENCODE(BT_UUID_BAS_VAL),
				  BT_UUID_16_ENCODE(BT_UUID_DIS_VAL)),
#if defined(CONFIG_BT_EXT_ADV)
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME, sizeof(CONFIG_BT_DEVICE_NAME) - 1),
#endif /* CONFIG_BT_EXT_ADV */
};

#if !defined(CONFIG_BT_EXT_ADV)
static const struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME, sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};
#endif /* !CONFIG_BT_EXT_ADV */

#define BT_UUID_LED_SERVICE_VAL \
	BT_UUID_128_ENCODE(0xde8a5aac, 0xa99b, 0xc315, 0x0c80, 0x60d4cbb51224)

#define BT_UUID_LED_CHAR_VAL \
	BT_UUID_128_ENCODE(0x5b026510, 0x4088, 0xc297, 0x46d8, 0xbe6c736a087a)

#define BT_UUID_LED_REPORT_CHAR_VAL \
	BT_UUID_128_ENCODE(0x61a885a4, 0x41c3, 0x60d0, 0x9a53, 0x6d652a70d29c)

static struct bt_uuid_128 led_service_uuid =
	BT_UUID_INIT_128(BT_UUID_LED_SERVICE_VAL);

static struct bt_uuid_128 led_char_uuid =
	BT_UUID_INIT_128(BT_UUID_LED_CHAR_VAL);

static struct bt_uuid_128 led_report_char_uuid =
	BT_UUID_INIT_128(BT_UUID_LED_REPORT_CHAR_VAL);

enum{
	LED_SVC_ATTR_SVC,
	LED_SVC_ATTR_CTRL_CHAR,
	LED_SVC_ATTR_CTRL_VALUE,
	LED_SVC_ATTR_REP_CHAR,
	LED_SVC_ATTR_REP_VALUE,
	LED_SVC_ATTR_REP_CCC,
};

static uint8_t led_value = 1;

static void btapp_gatt_attr_changed(const struct bt_gatt_attr *attr,
									const void *value,
									uint16_t len);

static ssize_t btapp_write_led(struct bt_conn *conn,
							   const struct bt_gatt_attr *attr,
							   const void *buf,
							   uint16_t len,
							   uint16_t offset,
							   uint8_t flags);

static ssize_t btapp_read_led(struct bt_conn *conn,
							  const struct bt_gatt_attr *attr,
							  void *buf,
							  uint16_t len,
							  uint16_t offset);

static void btapp_led_report_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value);

static void btapp_set_led_state(uint8_t state);

BT_GATT_SERVICE_DEFINE(led_svc,
		BT_GATT_PRIMARY_SERVICE(&led_service_uuid),
		BT_GATT_CHARACTERISTIC(&led_char_uuid.uuid,
							   BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
							   BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
							   btapp_read_led,
							   btapp_write_led,
							   &led_value),
		BT_GATT_CHARACTERISTIC(&led_report_char_uuid.uuid,
							   BT_GATT_CHRC_NOTIFY,
							   BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
							   NULL,
							   NULL,
							   &led_value),
		BT_GATT_CCC(btapp_led_report_ccc_cfg_changed,
					BT_GATT_PERM_READ | BT_GATT_PERM_WRITE)
);

enum {
	STATE_CONNECTED,
	STATE_DISCONNECTED,

	STATE_BITS,
};

static void btapp_connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		printk("Connection failed, err 0x%02x %s\n", err, bt_hci_err_to_str(err));
	} else {
		printk("Connected\n");

		current_conn = conn;
	}
}

static void btapp_disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("Disconnected, reason 0x%02x %s\n", reason, bt_hci_err_to_str(reason));

	current_conn = NULL;

	k_poll_signal_raise(&signal, STATE_DISCONNECTED);
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = btapp_connected,
	.disconnected = btapp_disconnected,
};

static void btapp_auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Pairing cancelled: %s\n", addr);
}

static struct bt_conn_auth_cb auth_cb_display = {
	.cancel = btapp_auth_cancel,
};

static void btapp_bas_notify(void)
{
	uint8_t battery_level = bt_bas_get_battery_level();

	battery_level--;

	if (!battery_level) {
		battery_level = 100U;
	}

	bt_bas_set_battery_level(battery_level);
}

static void bat_timeout(struct k_work *work)
{
	ARG_UNUSED(work);

	btapp_bas_notify();
	k_work_schedule(&bat_work, BAT_NOT);
}

static void btapp_gatt_attr_changed(const struct bt_gatt_attr *attr,
									const void *value,
									uint16_t len)
{
	(void)value;
	(void)len;

	if (attr == &led_svc.attrs[LED_SVC_ATTR_CTRL_VALUE]) {
		printk("LED control changed\n");
		bt_gatt_notify(current_conn, &led_svc.attrs[LED_SVC_ATTR_REP_VALUE],
					   &led_value,
					   sizeof(led_value));
	} else if (attr == &led_svc.attrs[LED_SVC_ATTR_REP_VALUE]) {
		printk("LED report changed\n");
	}
	printk("LED value %d\n", led_value);

}

static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec btn = GPIO_DT_SPEC_GET(BTN0_NODE, gpios);
static struct gpio_callback button_cb_data;

static ssize_t btapp_write_led(struct bt_conn *conn,
							   const struct bt_gatt_attr *attr,
							   const void *buf,
							   uint16_t len,
							   uint16_t offset,
							   uint8_t flags)
{
	k_spinlock_key_t key;

	if (len != 1) {
		printk("Write error\n");
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);

	} else if (offset != 0) {
		printk("Write error\n");
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	key = k_spin_lock(&lock);

	btapp_set_led_state(((uint8_t *)buf)[0]);
	btapp_gatt_attr_changed(attr, NULL, 0);

	k_spin_unlock(&lock, key);

	return len;
}

static ssize_t btapp_read_led(struct bt_conn *conn,
							  const struct bt_gatt_attr *attr,
							  void *buf,
							  uint16_t len,
							  uint16_t offset)
{
	/* Read user data that is LED state */
	const uint8_t *val = attr->user_data;

	/* Read led state */
	return bt_gatt_attr_read(conn, attr, buf, len, offset, val, sizeof(*val));
}

static void btapp_led_report_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	bool led_report_notify_enabled;

	led_report_notify_enabled = (value == BT_GATT_CCC_NOTIFY);
	printk("LED Report notifications %s\n",
			led_report_notify_enabled ? "enabled" : "disabled");

	led_value = gpio_pin_get(led.port, led.pin);

	if (led_report_notify_enabled) {
		bt_gatt_notify(current_conn, &led_svc.attrs[LED_SVC_ATTR_REP_VALUE],
						&led_value,
						sizeof(led_value));
	}
}

static void btapp_set_led_state(uint8_t state)
{
	if (state > 0) {
		led_value = 1;
		gpio_pin_set(led.port, led.pin, 1);
	} else {
		led_value = 0;
		gpio_pin_set(led.port, led.pin, 0);
	}
}

static int btapp_led_setup(void)
{
	int err;

	printk("Checking LED device...");
	if (!gpio_is_ready_dt(&led)) {
		printk("failed.\n");
		return -EIO;
	}
	printk("done.\n");

	printk("Configuring GPIO pin...");
	err = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (err) {
		printk("failed.\n");
		return -EIO;
	}

	return 0;
}

static int btapp_button_setup(void)
{
	int err;

	printk("Checking button device...");
	if (!gpio_is_ready_dt(&btn)) {
		printk("failed.\n");
		return -EIO;
	}
	printk("done.\n");

	printk("Configuring GPIO pin...");
	err = gpio_pin_configure_dt(&btn, GPIO_INPUT | GPIO_PULL_UP);
	if (err) {
		printk("Failed to configure button pin.\n");
		return -EIO;
	}
	printk("done.\n");

	return 0;
}

static void button_pressed_isr(const struct device *dev,
							   struct gpio_callback *cb,
							   uint32_t pins)
{
	k_spinlock_key_t key = k_spin_lock(&lock);

	/* Simple: toggle LED using current state */
	btapp_set_led_state(!led_value);
	btapp_gatt_attr_changed(&led_svc.attrs[LED_SVC_ATTR_CTRL_VALUE],
					&led_value,
					sizeof(led_value));

	k_spin_unlock(&lock, key);
}

int main(void)
{
	struct k_poll_event events[1];
	int signaled, result;
	int err;

	k_poll_signal_init(&signal);
	k_poll_event_init(&events[0], K_POLL_TYPE_SIGNAL,
					K_POLL_MODE_NOTIFY_ONLY, &signal);

	err = btapp_led_setup();
	if (err) {
		return 0;
	}

	err = btapp_button_setup();
	if (err) {
		return 0;
	}

	/* Interrupt on edge (falling for active-low button with pull-up) */
	err = gpio_pin_interrupt_configure_dt(&btn, GPIO_INT_EDGE_TO_ACTIVE);
	if (err) {
		printk("Failed to configure button interrupt: %d\n", err);
		return 0;
	}

	gpio_init_callback(&button_cb_data,
						button_pressed_isr,
						BIT(btn.pin));

	err = gpio_add_callback(btn.port, &button_cb_data);
	if (err) {
		printk("Failed to register callback: %d\n", err);
		return 0;
	}

	printk("Button initialized\n");

	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}

	printk("Bluetooth initialized\n");

	bt_conn_auth_cb_register(&auth_cb_display);

/* BT_LE_ADV_CONN_FAST_1 */

#if !defined(CONFIG_BT_EXT_ADV)
	printk("Starting Legacy Advertising (connectable and scannable)\n");
	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return 0;
	}

#else /* CONFIG_BT_EXT_ADV */
	struct bt_le_adv_param adv_param = {
		.id = BT_ID_DEFAULT,
		.sid = 0U,
		.secondary_max_skip = 0U,
		.options = (BT_LE_ADV_OPT_EXT_ADV | BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_CODED),
		.interval_min = BT_GAP_ADV_FAST_INT_MIN_2,
		.interval_max = BT_GAP_ADV_FAST_INT_MAX_2,
		.peer = NULL,
	};
	struct bt_le_ext_adv *adv;

	printk("Creating a Coded PHY connectable non-scannable advertising set\n");
	err = bt_le_ext_adv_create(&adv_param, NULL, &adv);
	if (err) {
		printk("Failed to create Coded PHY extended advertising set (err %d)\n", err);

		printk("Creating a non-Coded PHY connectable non-scannable advertising set\n");
		adv_param.options &= ~BT_LE_ADV_OPT_CODED;
		err = bt_le_ext_adv_create(&adv_param, NULL, &adv);
		if (err) {
			printk("Failed to create extended advertising set (err %d)\n", err);
			return 0;
		}
	}

	printk("Setting extended advertising data\n");
	err = bt_le_ext_adv_set_data(adv, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		printk("Failed to set extended advertising data (err %d)\n", err);
		return 0;
	}

	printk("Starting Extended Advertising (connectable non-scannable)\n");
	err = bt_le_ext_adv_start(adv, BT_LE_EXT_ADV_START_DEFAULT);
	if (err) {
		printk("Failed to start extended advertising set (err %d)\n", err);
		return 0;
	}
#endif /* CONFIG_BT_EXT_ADV */

	printk("Advertising successfully started\n");

	/* Initialize battery level notification function */
	k_work_init_delayable(&bat_work, bat_timeout);

	/* Start battery level notification */
	k_work_schedule(&bat_work, BAT_NOT);

	while (1) {

		k_poll(events, 1, K_FOREVER);
		k_poll_signal_check(&signal, &signaled, &result);
		if (signaled && (result == STATE_DISCONNECTED)) {

#if !defined(CONFIG_BT_EXT_ADV)
			printk("Starting Legacy Advertising (connectable and scannable)\n");
			err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd,
					      ARRAY_SIZE(sd));
			if (err) {
				printk("Advertising failed to start (err %d)\n", err);
				return 0;
			}

#else /* CONFIG_BT_EXT_ADV */
			printk("Starting Extended Advertising (connectable and non-scannable)\n");
			err = bt_le_ext_adv_start(adv, BT_LE_EXT_ADV_START_DEFAULT);
			if (err) {
				printk("Failed to start extended advertising set (err %d)\n", err);
				return 0;
			}
#endif /* CONFIG_BT_EXT_ADV */
			k_poll_signal_reset(&signal);
			events[0].state = K_POLL_STATE_NOT_READY;
		}
	}

	return 0;
}
