.. zephyr:code-sample:: bt_blinky
   :name: Blueooth blinky (Peripheral)
   :relevant-api: bluetooth

Overview
********

Similar to the SOC Blinky sample, implements a simple custom GATT service with two characteristics.
One characteristic controls the state of the LED (ON/OFF) via write operations from a GATT client,
and the second characteristic sends notifications to subscribed clients when the button state changes
(pressed or released).

Requirements
************

* BlueZ running on the host, or
* A board with Bluetooth LE support

Building and Running
********************

Building a minimal variant
--------------------------

.. zephyr-app-commands::
   :zephyr-app: samples/bt_blinky
   :board: qemu_cortex_m3
   :goals: build
