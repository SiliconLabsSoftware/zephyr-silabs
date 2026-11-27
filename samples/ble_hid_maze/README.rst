.. zephyr:code-sample:: ble_hid_maze
   :name: Bluetooth LE HID mouse display maze
   :relevant-api: bluetooth display_interface

   Control a maze on an SPI display with a Bluetooth LE HID mouse.

Overview
********

This sample implements a small maze game that demonstrates:

* BLE central acting as a HID client;
* runtime parsing of a HID mouse report map;
* bonding and reconnection to one mouse;
* partial display updates without a full RGB frame buffer.

Move the mouse to guide the marker through the maze. Press the left mouse
button to restart the current maze or the right mouse button to load the next
maze. Each press triggers one action; holding a button while moving does not
repeat it.

Requirements
************

The sample currently supports these board and display setups:

* ``xg24_dk2601b`` with a DLC0347BWP00SF display;
* ``siwx917_dk2605a`` with a DLC0347BWP00SF display;
* ``xg24_rb4187c`` with a WPK board featuring an onboard Sharp 128 x 128
  memory display.

It also requires:

* a Bluetooth LE HID mouse.

The application has been tested with Logitech M196 and Logitech MX Master 3S.
Other Bluetooth LE HID mice may also work.

The ``xg24_dk2601b`` and ``siwx917_dk2605a`` setups also require:

* a DLC0347BWP00SF-1 display with an ST7796S-compatible controller;
* jumper wires for the board expansion header.

The bundled maze assets support 480 x 320 and 128 x 128 displays. The supplied
board overlays configure the DLC0347BWP00SF-1 as a 480 x 320 RGB565 display.

Before building fetch the Silicon Labs binary blobs:

.. code-block:: console

   west blobs fetch hal_silabs

The SiWx917 network processor must also contain compatible connectivity
firmware. See the board documentation for the firmware update procedure.

Wiring
******

Connect the display to the board expansion header as follows. Pin names in
parentheses are the GPIO signals selected by the board overlay.

.. list-table:: ``xg24_dk2601b`` connections
   :header-rows: 1

   * - Display signal
     - Expansion header
   * - VCC
     - EXP20 (3.3 V)
   * - GND
     - EXP01
   * - RESET
     - EXP13 (PD02)
   * - MOSI/SDA
     - EXP04 (PC03)
   * - D/C
     - EXP09 (PB00)
   * - CS
     - EXP10 (PA07)
   * - SCLK/SCL
     - EXP08 (PC01)

.. list-table:: ``siwx917_dk2605a`` connections
   :header-rows: 1

   * - Display signal
     - Expansion header
   * - VCC
     - EXP20 (3.3 V)
   * - GND
     - EXP01 or EXP26
   * - RESET
     - EXP23
   * - MOSI/SDA
     - EXP07
   * - D/C
     - EXP21
   * - CS
     - EXP09
   * - SCLK/SCL
     - EXP03

Building and Running
********************

Build and flash the sample for ``xg24_dk2601b``:

.. zephyr-app-commands::
   :zephyr-app: samples/ble_hid_maze
   :board: xg24_dk2601b
   :goals: build flash
   :compact:

Or build and flash it for ``siwx917_dk2605a``:

.. zephyr-app-commands::
   :zephyr-app: samples/ble_hid_maze
   :board: siwx917_dk2605a
   :goals: build flash
   :compact:

Or build and flash it for ``xg24_rb4187c``:

.. zephyr-app-commands::
   :zephyr-app: samples/ble_hid_maze
   :board: xg24_rb4187c
   :goals: build flash
   :compact:

Pairing and Operation
*********************

#. Reset the board.
#. Press Button0 on the board. The status LED blinks quickly while pairing mode
   is enabled.
#. Put the mouse into Bluetooth pairing mode and keep it close to the board.
#. Move the mouse to guide the marker through the maze.

New peers must advertise the HID service, either in their connectable
advertisement or its scan response. On every connection, including reconnects
after a reset, the sample validates the mouse report map and waits for the
notification subscription to succeed before accepting the mouse.

Temporary read or connection errors disconnect the peer and retry after a short
delay, retaining its bond. A missing HID service or unsupported report map
causes the peer's bond to be removed, regardless of when it was created.
Scanning continues within the remaining pairing window.

If starting the scanner fails, the sample makes up to three attempts, spaced
1.5 seconds apart. Invalid parameters or unsupported scanning fail immediately.
These retries preserve the bond and do not extend the pairing window. A
successful scan can continue waiting for the bonded mouse without consuming
further attempts. If scan startup cannot recover, the LED stays on and the
console reports the error. Press Button0 to clear the bond and start fresh
pairing, or reset the board if its Bluetooth controller is unresponsive.

If a disconnect request fails, it is retried up to three times. If all attempts
fail, the LED stays on and the console reports the error. Press Button0 to retry
recovery and enable pairing; reset the board if its Bluetooth controller remains
unresponsive.

Bond information is stored in flash, so subsequent boots reconnect to the
bonded mouse automatically. Every press of Button0 starts fresh pairing: the
sample waits for any current connection to close, clears the stored bond, and
opens a 60-second pairing window. Put the desired mouse into pairing mode too.
The same action can replace the mouse or re-pair the existing mouse after key
loss. Button release and hold duration have no separate action.

The LED stays on while waiting for disconnection or if bond removal fails. The
console reports any failure; pressing Button0 retries the operation. Pairing
starts, with fast blinking, only after the bond has been cleared. A press during
startup is applied after Bluetooth and settings are ready.

Pressing Button0 again restarts fresh pairing and its timeout. A successfully
validated mouse ends the pairing window and stays connected. Timing out cannot
restore the cleared bond; the old mouse must be paired again to use it. The
sample stores one bond.

The application logs Bluetooth and game status on the virtual COM port at
115200 baud.

Implementation Notes
********************

The input module converts mouse button states into press events before queuing
them for the game. Queue flushing during a maze reload retains button history;
each new mouse connection resets that history and discards old queued input.
The queue keeps the newest input when full, so click events can still be
discarded during overflow or a maze reload.

The HID parser supports one mouse application input report containing buttons
1 and 2 and signed relative X/Y fields of up to 16 bits. Absolute pointing
devices and joysticks are not accepted. Collection nesting is limited to eight
levels; HID global Push/Pop layouts are reported as unsupported. This keeps the
sample focused on the mouse controls used by the maze.

The client selects a notifying Input Report whose Report Reference ID matches
the parsed mouse report (ID zero when the map has no Report IDs). Report
Reference and CCC lookups stay between that characteristic's value and the next
characteristic declaration, or the confirmed end of the HID service. Output,
Feature and unrelated Input Reports are skipped. Report IDs are obtained from
the descriptor; notifications are decoded as report data without a leading
Report ID byte.

The application does not allocate a complete RGB565 frame buffer. Maze images
are stored in flash and written to the display one row at a time. A one-bit
canvas records the marker trail. During movement, only a small rectangle around
the marker is reconstructed from the background, trail, and marker layers and
sent to the display.

The generated ``src/bg_*`` files contain RGB565 images for the supported
resolutions. Their image sources are in ``images`` folder. When
exporting an image with GIMP, export it as a C source file and select the
RGB565 (16-bit) option and add like ``bg_hex`` for prefix in the export settings.

Reproducing the Background Images
=================================

The source mazes were created with the `online maze generator
<https://codebox.net/pages/maze-generator/online>`_ using the settings below.

For the 320 x 240 source images:

.. list-table::
   :header-rows: 1

   * - Maze
     - Grid size
     - Seed
   * - Square
     - 14 x 10
     - 857133801
   * - Triangle
     - 22 x 10
     - 741051981
   * - Hex
     - 12 x 10
     - 620715798

For the 128 x 128 source images:

.. list-table::
   :header-rows: 1

   * - Maze
     - Grid size
     - Seed
   * - Square
     - 7 x 7
     - 446683954
   * - Triangle
     - 10 x 7
     - 991189289
   * - Hex
     - 4 x 5
     - 396377894

The images were downloaded from the generator, edited and polished in GIMP,
and then exported as C source files.

Limitations
***********

The HID parser supports mice whose input report describes relative X and Y
axes plus the first two buttons. It selects a single report and does not yet
interpret every HID global item or composite-device report layout.
