.. zephyr:code-sample:: comparator
   :name: Comparator
   :relevant-api: comparator

Overview
********

The sample code prints the comparator output to a terminal
on a regular bases.
The input is ported to a board specific pin. If this pin is
delivered 3V3 voltage that triggers the comparator to print
this changes.

Requirements
************

Building and Running
********************

Building a minimal variant
--------------------------

.. zephyr-app-commands::
   :zephyr-app: samples/comparator
   :board: qemu_cortex_m3
   :goals: build
