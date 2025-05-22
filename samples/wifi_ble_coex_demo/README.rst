.. zephyr:code-sample:: wifi_ble_coex_throughput
   :name: Wifi Ble Coex Throughput
   :relevant-api: wifi, bluetooth

    Demonstrate throughput performance with concurrent Wi-Fi and Bluetooth LE usage.

Overview
********

Application demonstrating coexistence of Wi-Fi and Bluetooth LE functionality by measuring throughput performance when both radios are active. This sample can be used to evaluate how well the system handles concurrent communication, such as a BLE peripheral connection running while a Wi-Fi connects to a particular Access Point[AP].

Requirements
************

* BlueZ running on the host, or
* A board with Bluetooth LE and Wi-Fi support.
* Any mobile Application to check the connectivity of ble and wifi [Eg:- SiConnect].

Building and Running
********************
This sample can be found under :zephyr_file:`samples/bluetooth/wifi_ble_coex_throughput`
in the Zephyr-silabs tree.


See :zephyr:code-sample-category:`bluetooth` samples for details.


Test the Application
********************
* Build the application.
* Flash and run  the application.

Steps: Connect to Wi-Fi, pair over BLE, and measure throughput on both to test coexistence.
********************************************************************************            ***********
Bluetooth:
1. Open any serial console to view logs.
2. After successfully flashing the SiWx91x, it will begin advertising as "BLE_THROUGHPUT".
3. Launch a BLE app like Si Connect on your phone or PC.
4. Scan for available devices and connect to "BLE_THROUGHPUT".
5. Enable notifications to start data transmission. After a while, disable notifications — the BLE throughput will be displayed in the serial console logs.

Wi-Fi:
1. Configure the Access Point name (SSID) and password (PWD) in the main file for the AP you want to connect to.
2. After flashing the SiWx91x, the device will scan for the specified AP and attempt to connect if found.
3. Once connected, the SiWx91x transmits data (as defined in main) to calculate throughput. The Wi-Fi throughput results will then be displayed in the serial console logs.
