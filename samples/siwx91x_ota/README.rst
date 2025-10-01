# Copyright (c) 2025 Silicon Laboratories Inc.
# SPDX-License-Identifier: Apache-2.0

.. zephyr:code-sample:: siwx91x_otas
   :name: HTTP OTA Firmware Update on SiWx917
   :relevant-api: wifi

   Demonstrates HTTP/HTTPS OTA firmware update using SiWx917 on Zephyr.

Overview
********

Application demonstrates how to perform HTTP/HTTPS OTA firmware updates on the
SiWx917 platform using Zephyr RTOS. It connects to a Wi-Fi network, establishes
a secure HTTPS connection using a CA certificate, and downloads firmware
updates from a remote server. The application showcases secure connectivity and
OTA update mechanisms for IoT devices.

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
  * ``CONFIG_OTA_WIFI_SECURITY_TYPE`` - wifi security type (0 - no security, 1 - WPA2-PSK security)
  * ``CONFIG_OTA_IP_PROTOCOL_SELECTION`` - Select IPv4 or IPv6

* OTA Server Settings
  * ``CONFIG_OTA_SERVER_IP`` or ``CONFIG_OTA_SERVER_HOSTNAME`` - Server address
  * ``CONFIG_OTA_SERVER_PORT`` - Server port
  * ``CONFIG_OTA_RPS_FILE`` - Firmware file on server
  * ``CONFIG_OTA_HTTPS_SUPPORT`` - Enable HTTPS (default: disabled)
  * ``CONFIG_OTA_USE_DNS_RESOLVER`` - Enable DNS resolution (set to 1 to use
    ``CONFIG_OTA_SERVER_HOSTNAME``)

.. _signed image generation:
   https://docs.zephyrproject.org/latest/kconfig.html#CONFIG_SIWX91X_SIGN_KEY

Building and Running
********************

1. Configure required settings
2. Build and Flash

   .. code-block:: console

      west build -b siwx917_rb4338a siwx917_ota -p
      west flash

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
