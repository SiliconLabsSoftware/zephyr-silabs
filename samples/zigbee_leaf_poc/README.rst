Silicon Labs Zigbee leaf PoC
==============================

This downstream sample validates linking the Silicon Labs Zigbee PRO leaf
stack prebuilt libraries from the ``hal_silabs`` blob bundle.

Requirements
------------

* A Silicon Labs Series 2 board with a 2.4 GHz radio, such as ``xg24_rb4186c``
* The ``hal_silabs`` module blobs fetched via west (``west blobs fetch hal_silabs``)

Building
--------

.. code-block:: console

   west build -b xg24_rb4186c zephyr-silabs-internal/samples/zigbee_leaf_poc

The sample enables ``CONFIG_ZIGBEE_SILABS`` and links the leaf stack variant.
Additional Zigbee SDK sources under ``simplicity_sdk/protocol/zigbee`` and
Zephyr runtime glue are still required for a functional Zigbee network.
