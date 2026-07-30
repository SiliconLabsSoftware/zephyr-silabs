Silicon Labs Zigbee Z3 Light
==============================

This downstream sample ports the Silicon Labs ``zigbee_z3_light`` reference
application to Zephyr. It links the Zigbee PRO stack prebuilt libraries from
the ``hal_silabs`` blob bundle and enables the Z3 Light component profile.

Requirements
------------

* A Silicon Labs Series 2 board with a 2.4 GHz radio, such as ``xg24_rb4186c``
* The ``hal_silabs`` module blobs fetched via west (``west blobs fetch hal_silabs``)

Building
--------

.. code-block:: console

   west build -b xg24_rb4186c zephyr-silabs-internal/samples/zigbee_z3_light

The sample enables ``CONFIG_ZIGBEE_SILABS`` and links the coordinator stack
variant used by the Z3 Light profile. Zigbee SDK sources live in the
``hal_silabs`` module; Zephyr port glue and generated component Kconfig live
under ``zephyr-silabs-internal/modules/hal_silabs/simplicity_sdk/zigbee/``.

``CONFIG_SILABS_SISDK_ZIGBEE_DEBUG_PRINT`` is disabled in ``prj.conf`` until a
``printf.h`` shim is added. The prebuilt ``CONFIG_ZIGBEE_SILABS_DEBUG_BASIC``
blob remains enabled.

ZAP autogen files (endpoints, clusters, dispatchers) are vendored under
``samples/zigbee_z3_light/autogen/``. Refresh them after regenerating the Z3
Light project in Simplicity Studio::

   rsync -a --delete \
     ~/repos/zigbee/zigbee_app/z3/zigbee_z3_light/build/z3light_4186c/autogen/ \
     zephyr-silabs-internal/samples/zigbee_z3_light/autogen/

Regenerate component enables after updating the Simplicity Studio catalog::

   python3 modules/hal/silabs/scripts/gen_zigbee_components.py --no-copy \
     --zigbee-root ~/repos/zigbee \
     --active-catalog-header <path-to>/autogen/sl_component_catalog.h \
     --overlay-root zephyr-silabs-internal/modules/hal_silabs \
     --prj-conf-out zephyr-silabs-internal/samples/zigbee_z3_light/prj_z3_light_components.conf
