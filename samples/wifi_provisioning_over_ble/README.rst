.. zephyr:code-sample:: wifi_provisioning_over_ble
   :name: Wi-Fi Provisioning over BLE
   :relevant-api: wifi, bluetooth

   Provision Wi-Fi credentials over Bluetooth LE.

Overview
********

Application demonstrating Wi-Fi provisioning over Bluetooth Low Energy (BLE). The application starts in BLE mode, allowing a mobile application or central device to send Wi-Fi credentials to the target. Once received, the device attempts to connect to the specified Wi-Fi Access Point (AP).

Requirements
************

* BlueZ running on the host, or
* A board with Bluetooth LE and Wi-Fi support.
* A mobile app or central device to send Wi-Fi credentials over BLE
* Wi-Fi Access Point for connectivity testing.

Thread Priority Guidelines
**************************
* The Wi-Fi application thread must have **lower priority** than the Wi-Fi thread to ensure smooth and uninterrupted Wi-Fi operations.

Building and Running
********************
This sample can be found under :zephyr_file:`samples/wifi_provisioning_over_ble`
in the zephyr-silabs tree.

See :zephyr:code-sample-category:`bluetooth` samples for details.

Test the Application
********************
* Build the application.
* Flash and run  the application.

Steps to verify the WLAN ACCESSPOINT[AP] connection over BLE Provisioning Example
*********************************************************************************
* Steps to be followed to verify WLAN AP connection over BLE Provisioning with Android Simplicity Connect Application.
   1. Configure the Access point in OPEN/WPA-PSK/WPA2-PSK/WPA3 mode to connect the SiWx91x.
   2. Connect any serial console for prints.
   3. When SiWx91x  enters BLE advertising mode, launch the Simplicity Connect App.
   4. Click on Demo and select Wifi-Commissioning tile.
   5. The Si917 advertises as the "BLE_CONFIGURATOR". Click on "BLE_CONFIGURATOR".
   6. Once the BLE got the connected, list of available Access Points in the vicinity, get displayed on the screen.
   7. Select the AP from the scanned list as shown below.
   8. If the selected AP is configured in the security, the password entry pop-up window will be appeared.
   9. Enter the password and click on "CONNECT".
   10. Connect to an Access Point, once the SiWx91x EVK gets connected to AP, IP address of SiWx91x EVK get displayed on the screen.
   11. To disconnect from Access Point, click on connected AP and click on YES.
   12. Refer the below figure for console prints.
