Silicon Labs Zigbee Z3 Light
==============================

This downstream sample ports the Silicon Labs ``zigbee_z3_light`` reference
application to Zephyr. It links the Zigbee PRO stack prebuilt libraries from
the ``hal_silabs`` blob bundle and enables the Z3 Light component profile.

Requirements
------------

* A Silicon Labs Series 2 board with a 2.4 GHz radio, such as ``xg24_rb4186c``
* The ``hal_silabs`` module blobs fetched via west (``west blobs fetch hal_silabs``)
* The ``hal_silabs_extra`` module (MSLA Zigbee SDK sources and Z3 Light ZAP autogen)

Building
--------

.. code-block:: console

   west build -b xg24_rb4186c zephyr-silabs-internal/samples/zigbee_z3_light

The sample enables ``CONFIG_ZIGBEE_SILABS`` and links the coordinator stack
variant used by the Z3 Light profile. Zigbee SDK sources live in
``hal_silabs_extra``; Zephyr port glue and generated component Kconfig live
under ``zephyr-silabs-internal/modules/hal_silabs/simplicity_sdk/zigbee/``.

ZAP / Studio autogen
--------------------

ZAP endpoint/cluster/CLI autogen is MSLA content and is vendored under
``modules/hal/silabs_extra/samples/zigbee_z3_light/autogen/`` (not in this
public sample tree). Refresh after regenerating the Z3 Light project in
Simplicity Studio::

   rsync -a --delete \
     ~/repos/zigbee/zigbee_app/z3/zigbee_z3_light/build/z3light_4186c/autogen/ \
     modules/hal/silabs_extra/samples/zigbee_z3_light/autogen/

Regenerate component enables after updating the Simplicity Studio catalog::

   python3 modules/hal/silabs/scripts/gen_zigbee_components.py \
     --zigbee-root ~/repos/zigbee \
     --slcp ~/repos/zigbee_app/z3/zigbee_z3_light/zigbee_z3_light.slcp \
     --overlay-root zephyr-silabs-internal/modules/hal_silabs \
     --prj-conf-out zephyr-silabs-internal/samples/zigbee_z3_light/prj_z3_light_components.conf
