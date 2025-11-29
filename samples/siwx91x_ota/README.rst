# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

.. zephyr:code-sample:: siwx91x_ota
   :name: HTTP OTA Firmware Update on SiWx917
   :relevant-api: wifi

   Demonstrates HTTP/HTTPS OTA firmware update using SiWx917 on Zephyr.

Overview
********

Application demonstrates how to perform HTTP/HTTPS OTA firmware updates on the
SiWx917 platform using Zephyr RTOS. It connects to a Wi-Fi network, establishes
an HTTPS connection, and downloads and flashes firmware updates from a remote
server. The application showcases secure connectivity, secure boot, signature
checks, and HTTP/HTTPS OTA update mechanisms for IoT devices.

This application supports signed images. More information about the signing
process is available on :ref:`west-sign`.

Requirements
************

* SiWx917 development board with Wi-Fi support
* HTTP server

Configurations
**************

The following configurations can be modified in ``prj.conf``:

* Wi-Fi Settings
  * ``CONFIG_OTA_WIFI_SSID`` - Network name
  * ``CONFIG_OTA_WIFI_PSK`` - Network password
  * ``CONFIG_OTA_UPDATE_URL`` - OTA update URL

Building and Running
********************

1. Configure required settings
2. Build and Flash

   .. zephyr-app-commands::
      :app: siwx91x_ota
      :board: siwx917_rb4338a
      :goals: build flash

3. Run HTTP/HTTPS server

Test the Application
********************

1. After flashing the SiWx91x, the device will scan for the specified AP and
   attempt to connect if found.
2. Once connected, the SiWx91x will initiate an HTTP/S connection to the specified
   server and download the firmware binary.
3. The OTA update process will be logged to the serial console.

Note
****

This application is not for production.
