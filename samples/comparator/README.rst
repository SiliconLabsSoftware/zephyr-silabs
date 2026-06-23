.. zephyr:code-sample:: comparator
   :name: Comparator
   :relevant-api: comparator

Overview
********

The sample code prints the comparator output to a terminal
on a regular basis.
The input is ported to a board specific pin. If 3.3 V is
delivered to this pin the comparator triggers and the
change is printed.

Building and Running
********************

Building a minimal variant
--------------------------

.. zephyr-app-commands::
   :zephyr-app: samples/comparator
   :goals: build

See 'boards' directory for supported boards
