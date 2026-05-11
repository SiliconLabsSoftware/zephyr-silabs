/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/comparator.h>
#include <zephyr/pm/device_runtime.h>
#include <zephyr/sys/printk.h>

static void acmp_cb(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);
	int out = comparator_get_output(dev);

	printk("Comparator triggered, output=%d\n", out);
}

int main(void)
{
	const struct device *cmp = DEVICE_DT_GET(DT_NODELABEL(acmp0));

	if (!device_is_ready(cmp)) {
		printk("ACMP device not ready\n");
		return 0;
	}

	/* Comparator docs say the device is active when resumed */
	ret = pm_device_runtime_enable(cmp);
	if (ret < 0) {
		printk("Failed to runtime enable ACMP: %d\n", ret);
		return 0;
	}

	ret = pm_device_runtime_get(cmp);
	if (ret < 0) {
		printk("pm_device_runtime_get failed: %d\n", ret);
		return 0;
	}

	/* Optional: read current comparator output */
	ret = comparator_get_output(cmp);
	if (ret < 0) {
		printk("comparator_get_output failed: %d\n", ret);
		return 0;
	}

	printk("Initial comparator output = %d\n", ret);

	/* Optional: enable edge trigger */
	ret = comparator_set_trigger(cmp, COMPARATOR_TRIGGER_BOTH_EDGES);
	if (ret < 0) {
		printk("comparator_set_trigger failed: %d\n", ret);
		return 0;
	}

	/* Optional: register callback */
	ret = comparator_set_trigger_callback(cmp, acmp_cb, NULL);
	if (ret < 0) {
		printk("comparator_set_trigger_callback failed: %d\n", ret);
		return 0;
	}

	while (1) {
		k_sleep(K_SECONDS(1));

		ret = comparator_get_output(cmp);
		if (ret >= 0) {
			printk("Comparator output = %d\n", ret);
		}

		ret = comparator_trigger_is_pending(cmp);
		if (ret > 0) {
			printk("Trigger was pending\n");
		}
	}
}
