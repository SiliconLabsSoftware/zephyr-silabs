# Z3 Light Zigbee Component Report

Generated from the selected Zigbee application profile (.slcp or sl_component_catalog.h).

## Active Zigbee Components

| Component | Scope | Kconfig | Hard Kconfig deps | Cyclic deps |
| --- | --- | --- | --- | --- |
| `zigbee_application_bootloader` | `app_framework` | `SILABS_SISDK_ZIGBEE_APPLICATION_BOOTLOADER` | - | - |
| `zigbee_basic` | `app_framework` | `SILABS_SISDK_ZIGBEE_BASIC` | - | - |
| `zigbee_cli` | `app_framework` | `SILABS_SISDK_ZIGBEE_CLI` | - | - |
| `zigbee_cluster_service` | `app_framework` | `SILABS_SISDK_ZIGBEE_CLUSTER_SERVICE` | - | - |
| `zigbee_color_control_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_COLOR_CONTROL_SERVER` | - | - |
| `zigbee_core_cli` | `app_framework` | `SILABS_SISDK_ZIGBEE_CORE_CLI` | `SILABS_SISDK_ZIGBEE_CLI` | - |
| `zigbee_counters` | `app_framework` | `SILABS_SISDK_ZIGBEE_COUNTERS` | - | - |
| `zigbee_debug_basic` | `stack` | `SILABS_SISDK_ZIGBEE_DEBUG_BASIC_COMPONENT` | - | - |
| `zigbee_debug_basic_library` | `stack` | `SILABS_SISDK_ZIGBEE_DEBUG_BASIC_LIBRARY` | - | - |
| `zigbee_debug_print` | `app_framework` | `SILABS_SISDK_ZIGBEE_DEBUG_PRINT` | - | - |
| `zigbee_device_config` | `app_framework` | `SILABS_SISDK_ZIGBEE_DEVICE_CONFIG` | - | - |
| `zigbee_enhanced_routing` | `app_framework` | `SILABS_SISDK_ZIGBEE_ENHANCED_ROUTING` | - | - |
| `zigbee_find_and_bind_target` | `app_framework` | `SILABS_SISDK_ZIGBEE_FIND_AND_BIND_TARGET` | - | - |
| `zigbee_gp` | `stack` | `SILABS_SISDK_ZIGBEE_GP` | - | - |
| `zigbee_gp_library` | `stack` | `SILABS_SISDK_ZIGBEE_GP_LIBRARY` | - | - |
| `zigbee_green_power_client` | `app_framework` | `SILABS_SISDK_ZIGBEE_GREEN_POWER_CLIENT` | `SILABS_SISDK_ZIGBEE_GP`, `SILABS_SISDK_ZIGBEE_GREEN_POWER_COMMON` | - |
| `zigbee_green_power_client_cli` | `app_framework` | `SILABS_SISDK_ZIGBEE_GREEN_POWER_CLIENT_CLI` | - | - |
| `zigbee_green_power_common` | `app_framework` | `SILABS_SISDK_ZIGBEE_GREEN_POWER_COMMON` | `SILABS_SISDK_ZIGBEE_GP` | - |
| `zigbee_groups_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_GROUPS_SERVER` | - | - |
| `zigbee_identify` | `app_framework` | `SILABS_SISDK_ZIGBEE_IDENTIFY` | - | - |
| `zigbee_interpan` | `app_framework` | `SILABS_SISDK_ZIGBEE_INTERPAN` | - | - |
| `zigbee_level_control` | `app_framework` | `SILABS_SISDK_ZIGBEE_LEVEL_CONTROL` | - | - |
| `zigbee_network_creator` | `app_framework` | `SILABS_SISDK_ZIGBEE_NETWORK_CREATOR` | `SILABS_SISDK_ZIGBEE_SCAN_DISPATCH`, `SILABS_SISDK_ZIGBEE_NETWORK_CREATOR_SECURITY` | - |
| `zigbee_network_creator_security` | `app_framework` | `SILABS_SISDK_ZIGBEE_NETWORK_CREATOR_SECURITY` | - | - |
| `zigbee_network_steering` | `app_framework` | `SILABS_SISDK_ZIGBEE_NETWORK_STEERING` | `SILABS_SISDK_ZIGBEE_SCAN_DISPATCH` | - |
| `zigbee_on_off` | `app_framework` | `SILABS_SISDK_ZIGBEE_ON_OFF` | - | - |
| `zigbee_phy_2_4` | `stack` | `SILABS_SISDK_ZIGBEE_PHY_2_4` | - | - |
| `zigbee_pro_stack` | `stack` | `SILABS_SISDK_ZIGBEE_PRO_STACK` | - | - |
| `zigbee_pro_stack_basic` | `stack` | `SILABS_SISDK_ZIGBEE_PRO_STACK_BASIC` | - | - |
| `zigbee_pro_stack_library` | `stack` | `SILABS_SISDK_ZIGBEE_PRO_STACK_LIBRARY` | - | - |
| `zigbee_reporting` | `app_framework` | `SILABS_SISDK_ZIGBEE_REPORTING` | - | - |
| `zigbee_scan_dispatch` | `app_framework` | `SILABS_SISDK_ZIGBEE_SCAN_DISPATCH` | - | - |
| `zigbee_scenes` | `app_framework` | `SILABS_SISDK_ZIGBEE_SCENES` | - | - |
| `zigbee_secure_key_storage` | `stack` | `SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE` | - | - |
| `zigbee_secure_key_storage_upgrade` | `stack` | `SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE_UPGRADE` | - | - |
| `zigbee_security_manager` | `stack` | `SILABS_SISDK_ZIGBEE_SECURITY_MANAGER` | `SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE` | - |
| `zigbee_signature_decode` | `app_framework` | `SILABS_SISDK_ZIGBEE_SIGNATURE_DECODE` | - | - |
| `zigbee_source_route` | `stack` | `SILABS_SISDK_ZIGBEE_SOURCE_ROUTE_COMPONENT` | - | - |
| `zigbee_source_route_library` | `stack` | `SILABS_SISDK_ZIGBEE_SOURCE_ROUTE_LIBRARY` | - | - |
| `zigbee_stack_common` | `stack` | `SILABS_SISDK_ZIGBEE_STACK_COMMON` | `SILABS_SISDK_ZIGBEE_STRONG_RANDOM_API_PSA`, `SILABS_SISDK_ZIGBEE_SECURITY_MANAGER` | - |
| `zigbee_stack_diagnostics` | `app_framework` | `SILABS_SISDK_ZIGBEE_STACK_DIAGNOSTICS` | - | - |
| `zigbee_strong_random_api_psa` | `stack` | `SILABS_SISDK_ZIGBEE_STRONG_RANDOM_API_PSA` | - | - |
| `zigbee_system_common` | `stack` | `SILABS_SISDK_ZIGBEE_SYSTEM_COMMON` | `SILABS_SISDK_ZIGBEE_ENHANCED_ROUTING`, `SILABS_SISDK_ZIGBEE_PHY_2_4` | - |
| `zigbee_system_common_app_framework` | `stack` | `SILABS_SISDK_ZIGBEE_SYSTEM_COMMON_APP_FRAMEWORK` | - | - |
| `zigbee_update_tc_link_key` | `app_framework` | `SILABS_SISDK_ZIGBEE_UPDATE_TC_LINK_KEY` | - | - |
| `zigbee_zcl_cli` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZCL_CLI` | `SILABS_SISDK_ZIGBEE_CLI`, `SILABS_SISDK_ZIGBEE_ZCL_FRAMEWORK_CORE` | - |
| `zigbee_zcl_framework_core` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZCL_FRAMEWORK_CORE` | `SILABS_SISDK_ZIGBEE_DEVICE_CONFIG`, `SILABS_SISDK_ZIGBEE_CLUSTER_SERVICE`, `SILABS_SISDK_ZIGBEE_SIGNATURE_DECODE`, `SILABS_SISDK_ZIGBEE_SYSTEM_COMMON_APP_FRAMEWORK` | - |
| `zigbee_zll` | `stack` | `SILABS_SISDK_ZIGBEE_ZLL` | - | - |
| `zigbee_zll_commissioning_common` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_COMMISSIONING_COMMON` | `SILABS_SISDK_ZIGBEE_ZLL`, `SILABS_SISDK_ZIGBEE_INTERPAN` | - |
| `zigbee_zll_commissioning_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_COMMISSIONING_SERVER` | `SILABS_SISDK_ZIGBEE_ZLL`, `SILABS_SISDK_ZIGBEE_INTERPAN`, `SILABS_SISDK_ZIGBEE_ZLL_COMMISSIONING_COMMON` | - |
| `zigbee_zll_identify_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_IDENTIFY_SERVER` | `SILABS_SISDK_ZIGBEE_IDENTIFY` | - |
| `zigbee_zll_level_control_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_LEVEL_CONTROL_SERVER` | `SILABS_SISDK_ZIGBEE_LEVEL_CONTROL` | - |
| `zigbee_zll_library` | `stack` | `SILABS_SISDK_ZIGBEE_ZLL_LIBRARY` | - | - |
| `zigbee_zll_on_off_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_ON_OFF_SERVER` | `SILABS_SISDK_ZIGBEE_ON_OFF` | - |
| `zigbee_zll_scenes_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_SCENES_SERVER` | `SILABS_SISDK_ZIGBEE_SCENES` | - |
| `zigbee_zll_utility_server` | `app_framework` | `SILABS_SISDK_ZIGBEE_ZLL_UTILITY_SERVER` | - | - |

## Dependency Cycles

1. `SILABS_SISDK_ZIGBEE_DEBUG_BASIC_COMPONENT`, `SILABS_SISDK_ZIGBEE_DEBUG_BASIC_LIBRARY`
2. `SILABS_SISDK_ZIGBEE_GP`, `SILABS_SISDK_ZIGBEE_GP_LIBRARY`
3. `SILABS_SISDK_ZIGBEE_NETWORK_STEERING`, `SILABS_SISDK_ZIGBEE_UPDATE_TC_LINK_KEY`
4. `SILABS_SISDK_ZIGBEE_PRO_STACK`, `SILABS_SISDK_ZIGBEE_PRO_STACK_BASIC`, `SILABS_SISDK_ZIGBEE_PRO_STACK_LIBRARY`, `SILABS_SISDK_ZIGBEE_STACK_COMMON`, `SILABS_SISDK_ZIGBEE_SYSTEM_COMMON`
5. `SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE`, `SILABS_SISDK_ZIGBEE_SECURE_KEY_STORAGE_UPGRADE`
6. `SILABS_SISDK_ZIGBEE_SOURCE_ROUTE_COMPONENT`, `SILABS_SISDK_ZIGBEE_SOURCE_ROUTE_LIBRARY`
7. `SILABS_SISDK_ZIGBEE_ZLL`, `SILABS_SISDK_ZIGBEE_ZLL_LIBRARY`

## Template Contributions With Functions

### `zigbee_basic`

- `cluster_service`: `service_function`=`sl_zigbee_af_basic_cluster_server_command_parse`

### `zigbee_color_control_server`

- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_color_control_server_init_callback`
- `cluster_service`: `service_function`=`sl_zigbee_af_color_control_cluster_server_command_parse`

### `zigbee_core_cli`

- `cli_command`: `handler`=`sli_zigbee_af_cli_info_command`
- `cli_command`: `handler`=`printAllLibraryStatus`
- `cli_command`: `handler`=`sli_zigbee_af_cli_bsend_command`
- `cli_command`: `handler`=`sli_zigbee_cli_send_command`
- `cli_command`: `handler`=`sli_zigbee_zcl_read_cli_command`
- `cli_command`: `handler`=`sli_zigbee_zcl_write_cli_command`
- `cli_command`: `handler`=`resetCommand`
- `cli_command`: `handler`=`sli_zigbee_cli_factory_reset_command`
- `cli_command`: `handler`=`sli_zigbee_af_cli_raw_command`
- `cli_command`: `handler`=`sli_zigbee_cli_send_command`
- `cli_command`: `handler`=`sli_zigbee_af_cli_send_using_multicast_binding_command`
- `cli_command`: `handler`=`sli_zigbee_af_cli_timesync_command`
- `cli_command`: `handler`=`sli_get_pti_radio_config` (condition: sl_rail_util_ieee802154_phy_select)
- `cli_command`: `handler`=`sli_zigbee_cli_get_active_phy_command` (condition: cli, sl_rail_util_ieee802154_phy_select)
- `cli_command`: `handler`=`sli_zigbee_cli_config_cca_mode_command`
- `cli_command`: `handler`=`sli_zigbee_cli_version_command`
- `cli_command`: `handler`=`endpointPrint`
- `cli_command`: `handler`=`enableDisableEndpoint`
- `cli_command`: `handler`=`enableDisableEndpoint`
- `cli_command`: `handler`=`printEvents`
- `cli_command`: `handler`=`getSetMfgToken`
- `cli_command`: `handler`=`getSetMfgToken`
- `cli_command`: `handler`=`blackListCommand` (condition: zigbee_simulation)

### `zigbee_counters`

- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_counter_rollover_callback`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_counters_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_counters_init_cb` (condition: zigbee_ezsp)
- `cli_command`: `handler`=`sl_zigbee_af_counters_print_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_print_counters_type_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_simple_print_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_clear_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_print_thresholds_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_set_threshold_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_reset_thresholds_command`
- `cli_command`: `handler`=`sl_zigbee_af_counters_send_request_command`

### `zigbee_debug_print`

- `cli_command`: `handler`=`sli_zigbee_debug_print_enable_stack_type_command`
- `cli_command`: `handler`=`sli_zigbee_debug_print_enable_core_type_command`
- `cli_command`: `handler`=`sli_zigbee_debug_print_enable_app_type_command`
- `cli_command`: `handler`=`sli_zigbee_debug_print_enable_zcl_type_command`
- `cli_command`: `handler`=`sli_zigbee_debug_print_enable_legacy_af_debug_type_command`

### `zigbee_find_and_bind_target`

- `cli_command`: `handler`=`sl_zigbee_af_find_and_bind_target_start_command`

### `zigbee_gp`

- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_d_gp_sent_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_gpep_incoming_message_callback` (condition: zigbee_ncp)

### `zigbee_green_power_client`

- `cluster_service`: `service_function`=`sl_zigbee_af_green_power_cluster_client_command_parse`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_green_power_client_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_green_power_client_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_green_power_client_init_cb`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_green_power_client_retrieve_attribute_and_craft_response`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_green_power_client_stack_status_callback`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_green_power_client_d_gp_sent_callback`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_green_power_client_gpep_incoming_message_callback`

### `zigbee_green_power_client_cli`

- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_set_proxy_entry`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_add_sink`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_add_groupcast_sink`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_remove_proxy_table_entry`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_add_sink`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_print_proxy_table`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_clear_proxy_table_command`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_duplicate_filtering_test`
- `cli_command`: `handler`=`sl_zigbee_af_green_power_client_set_key`

### `zigbee_groups_server`

- `cli_command`: `handler`=`sli_zigbee_af_groups_server_cli_print`
- `cli_command`: `handler`=`sli_zigbee_af_groups_server_cli_clear`
- `cluster_service`: `service_function`=`sl_zigbee_af_groups_cluster_server_command_parse`

### `zigbee_identify`

- `cli_command`: `handler`=`sli_zigbee_af_identify_cli_print`
- `cluster_service`: `service_function`=`sl_zigbee_af_identify_cluster_server_command_parse`

### `zigbee_interpan`

- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_interpan_mac_filter_match_message_callback`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_interpan_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_interpan_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_interpan_ncp_init_cb` (condition: zigbee_ezsp)
- `cli_command`: `handler`=`sli_zigbee_af_interpan_enable_command`
- `cli_command`: `handler`=`sli_zigbee_af_interpan_disable_command`
- `cli_command`: `handler`=`sli_zigbee_af_interpan_fragment_test_command`
- `cli_command`: `handler`=`sli_zigbee_af_interpan_set_message_timeout_command`
- `cli_command`: `handler`=`sli_zigbee_af_interpan_group_short_command`
- `cli_command`: `handler`=`sli_zigbee_af_interpan_group_short_command`
- `cli_command`: `handler`=`sli_zigbee_af_interpan_long_command`

### `zigbee_level_control`

- `cluster_service`: `service_function`=`sl_zigbee_af_level_control_cluster_server_command_parse`

### `zigbee_network_creator`

- `cli_command`: `handler`=`sl_zigbee_af_network_creator_start_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_creator_stop_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_creator_form_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_creator_channel_mask_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_creator_channel_mask_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_creator_channel_mask_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_creator_status_command`

### `zigbee_network_creator_security`

- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_network_creator_security_init_cb`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_network_creator_security_stack_status_callback`
- `zigbee_stack_callback`: `function_name`=`sl_zigbee_af_network_creator_security_zigbee_key_establishment_cb`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_set_joining_link_key_command`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_clear_joining_link_key_command`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_open_or_close_network_command`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_open_or_close_network_command`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_open_network_with_key_command`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_configure_distributed_key`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_set_install_code_require`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_allow_tc_rejoin_wellknown_key`
- `cli_command`: `handler`=`sli_zigbee_af_network_creator_security_set_tc_rejoin_wellknown_key_time_out`

### `zigbee_network_steering`

- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_network_steering_stack_status_callback`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_network_steering_init_callback`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_status_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_start_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_stop_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_set_preconfigured_key_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_channel_set_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_channel_add_or_subtract_command`
- `cli_command`: `handler`=`sl_zigbee_af_network_steering_channel_add_or_subtract_command`

### `zigbee_on_off`

- `cluster_service`: `service_function`=`sl_zigbee_af_on_off_cluster_server_command_parse`

### `zigbee_reporting`

- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_reporting_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_reporting_init_cb`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_reporting_stack_status_callback`
- `cli_command`: `handler`=`sli_zigbee_af_reporting_cli_print`
- `cli_command`: `handler`=`sli_zigbee_af_reporting_cli_clear`
- `cli_command`: `handler`=`sli_zigbee_af_reporting_cli_remove`
- `cli_command`: `handler`=`sli_zigbee_af_reporting_cli_add`
- `cli_command`: `handler`=`sli_zigbee_af_reporting_cli_clear_last_report_time`
- `cli_command`: `handler`=`sli_zigbee_af_reporting_cli_test_timing`

### `zigbee_scan_dispatch`

- `cli_command`: `handler`=`sli_zigbee_af_scan_dispatch_energy_scan_cli_command`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_scan_dispatch_init_callback`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_scan_dispatch_energy_scan_result_callback`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_scan_dispatch_scan_complete_callback`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_scan_dispatch_network_found_callback`

### `zigbee_scenes`

- `cli_command`: `handler`=`sli_plugin_scenes_server_print_info`
- `cli_command`: `handler`=`sli_plugin_scenes_server_clear`
- `cluster_service`: `service_function`=`sl_zigbee_af_scenes_cluster_server_command_parse`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_scenes_init`

### `zigbee_secure_key_storage_upgrade`

- `event_handler`: `handler`=`sli_zb_sec_man_upgrade_key_storage`

### `zigbee_source_route`

- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_source_route_set_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_source_route_get_configuration_value_command_cb`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_route_record_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_override_furthur_index_for_source_route_add_entry_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_override_incoming_route_record_callback` (condition: zigbee_ncp)

### `zigbee_stack_common`

- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_set_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_get_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_modify_memory_allocation_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_get_extended_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_set_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zigbee_pro_get_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_security_set_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_security_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_security_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_security_get_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_security_set_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_security_get_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_binding_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_binding_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_binding_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_binding_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sli_zigbee_initialize_binding_table`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_binding_permit_host_to_ncp_frame_cb`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_mac_filter_match_message_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_bootload_transmit_complete_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_bootload_message_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_raw_transmit_complete_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_mac_passthrough_message_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_id_conflict_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_network_status_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_route_error_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_many_to_one_route_request_cb` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_duty_cycle_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_child_join_cb` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_network_found_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_scan_complete_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_message_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_message_sent_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_switch_network_key_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zigbee_key_establishment_callback` (condition: zigbee_ncp)

### `zigbee_stack_diagnostics`

- `cli_command`: `handler`=`printInfo`
- `cli_command`: `handler`=`printChildTable`
- `cli_command`: `handler`=`printNeighborTable`
- `cli_command`: `handler`=`printRouteTable`

### `zigbee_system_common`

- `event_handler`: `handler`=`sli_zigbee_stack_init_callback`
- `event_handler`: `handler`=`sli_zigbee_app_framework_init_callback`
- `event_handler`: `handler`=`sli_zigbee_stack_rtos_task_init_cb` (condition: cmsis_rtos2)
- `event_handler`: `handler`=`sli_zigbee_stack_rtos_perm_allocation` (condition: sl_main, cmsis_rtos2)
- `event_handler`: `handler`=`sli_legacy_buffer_manager_initialize_buffers` (condition: sl_main)
- `event_handler`: `handler`=`sli_zigbee_stack_tick_callback`
- `event_handler`: `handler`=`sli_zigbee_app_framework_tick_callback`
- `event_handler`: `handler`=`sli_zigbee_stack_sleep_init` (condition: power_manager)
- `power_manager_handler`: `handler`=`sli_zigbee_app_framework_is_ok_to_sleep` (condition: power_manager, zigbee_zcl_framework_core)
- `power_manager_handler`: `handler`=`sli_zigbee_stack_is_ok_to_sleep` (condition: power_manager)
- `power_manager_handler`: `handler`=`sli_zigbee_stack_sleep_on_isr_exit` (condition: power_manager)
- `cli_command`: `handler`=`sl_zigbee_af_idle_sleep_status_command` (condition: power_manager, zigbee_zcl_framework_core)
- `cli_command`: `handler`=`sl_zigbee_af_idle_sleep_stay_awake_command` (condition: power_manager, zigbee_zcl_framework_core)
- `cli_command`: `handler`=`sl_zigbee_af_idle_sleep_awake_when_not_joined_command` (condition: power_manager, zigbee_zcl_framework_core)
- `cli_command`: `handler`=`sl_zigbee_af_idle_sleep_power_mode_performance_command` (condition: power_manager, zigbee_zcl_framework_core, device_series_3)
- `cli_command`: `handler`=`sl_zigbee_af_idle_sleep_power_mode_eco_command` (condition: power_manager, zigbee_zcl_framework_core, device_series_3)
- `cli_command`: `handler`=`sl_zigbee_af_radio_rx_duty_cycle_command` (condition: sl_rail_util_ieee802154_rx_duty_cycling, device_series_3)

### `zigbee_system_common_app_framework`

- `event_handler`: `handler`=`sli_zigbee_app_framework_rtos_task_init_cb` (condition: cmsis_rtos2)
- `event_handler`: `handler`=`sli_zigbee_app_framework_rtos_perm_allocation` (condition: sl_main, cmsis_rtos2)
- `event_handler`: `handler`=`sli_zigbee_app_framework_sleep_init` (condition: power_manager)
- `power_manager_handler`: `handler`=`sli_zigbee_af_sleep_on_isr_exit` (condition: power_manager)

### `zigbee_update_tc_link_key`

- `zigbee_stack_callback`: `function_name`=`sl_zigbee_af_update_tc_link_key_zigbee_key_establishment_cb`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_update_tc_link_key_begin_tc_link_key_update_init`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_update_tc_link_key_stack_status_callback`
- `cli_command`: `handler`=`sl_zigbee_af_set_tc_link_key_update_timer_command`
- `cli_command`: `handler`=`sl_zigbee_af_set_tc_link_key_update_retry_backoff_timer_command`
- `cli_command`: `handler`=`sl_zigbee_af_set_tc_link_key_update_now_command`
- `cli_command`: `handler`=`sl_zigbee_af_set_tc_link_key_update_max_attempts_per_iteration_command`
- `cli_command`: `handler`=`sl_zigbee_af_set_tc_link_key_update_max_iterations_command`

### `zigbee_zcl_cli`

- `zigbee_af_callback`: `function_name`=`sli_zigbee_zcl_cli_init`

### `zigbee_zcl_framework_core`

- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_zcl_framework_core_init_events_callback`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_service_discovery_init_events_callback`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_init`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_init_cb`
- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_network_init`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_stack_status_callback`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_incoming_message_callback`
- `cli_command`: `handler`=`networkFormCommand`
- `cli_command`: `handler`=`networkJoinCommand`
- `cli_command`: `handler`=`networkPermitJoinCommand`
- `cli_command`: `handler`=`networkLeaveCommand`
- `cli_command`: `handler`=`networkRejoinCommand`
- `cli_command`: `handler`=`networkRejoinDiffDeviceTypeCommand`
- `cli_command`: `handler`=`networkExtendedPanIdCommand`
- `cli_command`: `handler`=`networkCheckPjoinCommand`
- `cli_command`: `handler`=`networkPermitJoinCommand`
- `cli_command`: `handler`=`findJoinableNetworkCommand`
- `cli_command`: `handler`=`findUnusedPanIdCommand`
- `cli_command`: `handler`=`networkChangeChannelCommand`
- `cli_command`: `handler`=`networkSetCommand`
- `cli_command`: `handler`=`networkInitCommand`
- `cli_command`: `handler`=`networkIdCommand`
- `cli_command`: `handler`=`changeKeepAliveModeCommand`
- `cli_command`: `handler`=`networkChangeChildTimeoutOptionMaskCommand`
- `cli_command`: `handler`=`networkMultiPhyStartCommand`
- `cli_command`: `handler`=`networkMultiPhyStopCommand`
- `cli_command`: `handler`=`keysPrintCommand`
- `cli_command`: `handler`=`keysDeleteCommand`
- `cli_command`: `handler`=`keysClearCommand`
- `cli_command`: `handler`=`optionBindingTablePrintCommand`
- `cli_command`: `handler`=`optionBindingTableClearCommand`
- `cli_command`: `handler`=`optionBindingTableSetCommand`
- `cli_command`: `handler`=`optionPrintRxCommand`
- `cli_command`: `handler`=`optionPrintRxCommand`
- `cli_command`: `handler`=`optionRegisterCommand`
- `cli_command`: `handler`=`optionDiscoveryTargetCommand`
- `cli_command`: `handler`=`optionDiscoverCommand`
- `cli_command`: `handler`=`optionApsRetryCommand`
- `cli_command`: `handler`=`optionApsRetryCommand`
- `cli_command`: `handler`=`optionApsRetryCommand`
- `cli_command`: `handler`=`optionApsSecurityCommand`
- `cli_command`: `handler`=`optionApsSecurityCommand`
- `cli_command`: `handler`=`optionSecurityAllowTrustCenterRejoinUsingWellKnownKey`
- `cli_command`: `handler`=`optionSecurityAllowTrustCenterRejoinUsingWellKnownKeyTimeout`
- `cli_command`: `handler`=`optionSecuritySetKeyRequestPolicy`
- `cli_command`: `handler`=`changeKeyCommand`
- `cli_command`: `handler`=`changeKeyCommand`
- `cli_command`: `handler`=`optionLinkCommand`
- `cli_command`: `handler`=`optionInstallCodeCommand`
- `cli_command`: `handler`=`zdoRouteRequestCommand`
- `cli_command`: `handler`=`zdoPowerDescriptorRequestCommand`
- `cli_command`: `handler`=`zdoMgmtLqiCommand`
- `cli_command`: `handler`=`zdoMgmtBindCommand`
- `cli_command`: `handler`=`zdoLeaveRequestCommand`
- `cli_command`: `handler`=`zdoUnbindGroupCommand`
- `cli_command`: `handler`=`zdoUnbindUnicastCommand`
- `cli_command`: `handler`=`zdoActiveEpCommand`
- `cli_command`: `handler`=`zdoBindCommand`
- `cli_command`: `handler`=`zdoNodeCommand`
- `cli_command`: `handler`=`zdoMatchCommand`
- `cli_command`: `handler`=`zdoSimpleCommand`
- `cli_command`: `handler`=`zdoIeeeAddressRequestCommand`
- `cli_command`: `handler`=`zdoNwkAddressRequestCommand`
- `cli_command`: `handler`=`zdoNetworkUpdateScanCommand`
- `cli_command`: `handler`=`zdoNetworkUpdateSetCommand`
- `cli_command`: `handler`=`zdoNetworkUpdateScanCommand`
- `cli_command`: `handler`=`zdoNetworkUpdateChannelCommand`
- `cli_command`: `handler`=`zdoNetworkUpdateChannelCommand`
- `cli_command`: `handler`=`zdoAddClusterCommand`
- `cli_command`: `handler`=`zdoClearClusterCommand`
- `cli_command`: `handler`=`zdoAddClusterCommand`
- `cli_command`: `handler`=`zdoClearClusterCommand`
- `cli_command`: `handler`=`printAttributeTable`
- `cli_command`: `handler`=`printTimeCommand`

### `zigbee_zll`

- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zll_configuration_value_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zll_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zll_policy_command_cb`
- `zigbee_ncp_callback`: `function_name`=`sl_zigbee_xncp_zll_configuration_value_command_cb`
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zll_touch_link_target_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zll_address_assignment_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zll_scan_complete_callback` (condition: zigbee_ncp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zll_network_found_callback` (condition: zigbee_ncp)

### `zigbee_zll_commissioning_common`

- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_zll_commissioning_common_init_cb`
- `zigbee_af_callback`: `function_name`=`sl_zigbee_af_zll_commissioning_common_ncp_init_cb` (condition: zigbee_ezsp)
- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zll_commissioning_common_stack_status_callback`
- `cli_command`: `handler`=`formNetwork`
- `cli_command`: `handler`=`scanTouchLink`
- `cli_command`: `handler`=`scanTouchLink`
- `cli_command`: `handler`=`scanTouchLink`
- `cli_command`: `handler`=`abortTouchLink`
- `cli_command`: `handler`=`initiateTouchLink`
- `cli_command`: `handler`=`setIdentifyDuration`
- `cli_command`: `handler`=`endpointInformation`
- `cli_command`: `handler`=`getGroupIdentifiersRequest`
- `cli_command`: `handler`=`getEndpointListRequest`
- `cli_command`: `handler`=`printZllTokens`
- `cli_command`: `handler`=`setScanChannel`
- `cli_command`: `handler`=`setSecondaryScanChannel`
- `cli_command`: `handler`=`setScanMask`
- `cli_command`: `handler`=`statusCommand`
- `cli_command`: `handler`=`joinable`
- `cli_command`: `handler`=`unused`
- `cli_command`: `handler`=`resetToFactoryNew`
- `cli_command`: `handler`=`noTouchlinkForNFN`
- `cli_command`: `handler`=`noResetForNFN`
- `cli_command`: `handler`=`disable`
- `cli_command`: `handler`=`enable`
- `cli_command`: `handler`=`setRxOn`
- `cli_command`: `handler`=`cancelRxOn`
- `cli_command`: `handler`=`rxOnStatus`

### `zigbee_zll_commissioning_server`

- `zigbee_stack_callback`: `function_name`=`sli_zigbee_af_zll_touch_link_target_callback`

### `zigbee_zll_identify_server`

- `zigbee_af_callback`: `function_name`=`sli_zigbee_af_zll_identify_server_init_callback`
- `cluster_service`: `service_function`=`sl_zigbee_af_zll_identify_cluster_server_command_parse`

### `zigbee_zll_on_off_server`

- `cluster_service`: `service_function`=`sl_zigbee_af_zll_on_off_cluster_server_command_parse`

### `zigbee_zll_scenes_server`

- `cluster_service`: `service_function`=`sl_zigbee_af_zll_scenes_cluster_server_command_parse`

### `zigbee_zll_utility_server`

- `cluster_service`: `service_function`=`sl_zigbee_af_zll_commissioning_cluster_server_command_parse`

## Copied Zigbee Source Files

Total copied files: `376`

### `zigbee_basic`

- `app/framework/plugin/basic/basic-cb.c`
- `app/framework/plugin/basic/basic.c`

### `zigbee_cli`

- `app/util/serial/sl_zigbee_command_interpreter.c`

### `zigbee_cluster_service`

- `app/framework/service-function/sl_service_function.c`

### `zigbee_color_control_server`

- `app/framework/plugin/color-control-server/color-control-server-cb.c`
- `app/framework/plugin/color-control-server/color-control-server.c`

### `zigbee_counters`

- `app/framework/plugin/counters/af-counters.c`
- `app/framework/plugin/counters/counters-cb.c`
- `app/framework/plugin/counters/counters-ota.c`

### `zigbee_debug_print`

- `app/framework/plugin/debug-print/sl_zigbee_debug_print.c`

### `zigbee_enhanced_routing`

- `app/framework/common/zigbee_enhanced_routing.c`

### `zigbee_find_and_bind_target`

- `app/framework/plugin/find-and-bind-target/find-and-bind-target.c`

### `zigbee_green_power_client`

- `app/framework/plugin/green-power-client/green-power-client.c`

### `zigbee_green_power_common`

- `app/framework/plugin/green-power-common/green-power-common.c`

### `zigbee_groups_server`

- `app/framework/plugin/groups-server/groups-server-cb.c`
- `app/framework/plugin/groups-server/groups-server-common.c`
- `app/framework/plugin/groups-server/groups-server.c`

### `zigbee_identify`

- `app/framework/plugin/identify/identify-cb.c`
- `app/framework/plugin/identify/identify.c`

### `zigbee_interpan`

- `app/framework/plugin/interpan/interpan-cb.c`
- `app/framework/plugin/interpan/interpan-soc.c`
- `app/framework/plugin/interpan/interpan.c`

### `zigbee_level_control`

- `app/framework/plugin/level-control/level-control-cb.c`
- `app/framework/plugin/level-control/level-control.c`

### `zigbee_network_creator`

- `app/framework/plugin/network-creator/network-creator-cb.c`
- `app/framework/plugin/network-creator/network-creator.c`

### `zigbee_network_creator_security`

- `app/framework/plugin/network-creator-security/network-creator-security.c`

### `zigbee_network_steering`

- `app/framework/plugin/network-steering/network-steering-cb.c`
- `app/framework/plugin/network-steering/network-steering-v2.c`
- `app/framework/plugin/network-steering/network-steering.c`

### `zigbee_on_off`

- `app/framework/plugin/on-off/on-off-cb.c`
- `app/framework/plugin/on-off/on-off.c`

### `zigbee_reporting`

- `app/framework/plugin/reporting/reporting-cb.c`
- `app/framework/plugin/reporting/reporting-default-configuration.c`
- `app/framework/plugin/reporting/reporting.c`

### `zigbee_scan_dispatch`

- `app/framework/plugin/scan-dispatch/scan-dispatch.c`

### `zigbee_scenes`

- `app/framework/plugin/scenes/scenes-cb.c`
- `app/framework/plugin/scenes/scenes.c`

### `zigbee_secure_key_storage`

- `stack/security/zigbee-security-manager-vault-support.c`

### `zigbee_secure_key_storage_upgrade`

- `stack/security/zigbee-secure-key-storage-upgrade.c`

### `zigbee_security_manager`

- `stack/security/zigbee-security-manager.c`

### `zigbee_signature_decode`

- `app/framework/signature-decode/sl_signature_decode.c`

### `zigbee_stack_common`

- `app/util/counters/counters.c`
- `platform/service/legacy_hal_wdog/src/sl_legacy_hal_wdog_stub.c`
- `stack/config/sl_zigbee_callback_stubs.c`
- `stack/config/sl_zigbee_configuration.c`
- `stack/config/sl_zigbee_configuration_access.c`
- `stack/config/sl_zigbee_endpoint_stubs.c`
- `stack/core/multi-pan-common.c`
- `stack/core/multi-pan-stub.c`
- `stack/core/sl_zigbee_multi_network_stub.c`
- `stack/framework/debug-extended-stub.c`
- `stack/framework/zigbee-event-logger-stub-gen.c`
- `stack/internal/src/stubs/sl_zigbee_dhc_internal_weak_stubs.c`
- `stack/internal/src/stubs/sl_zigbee_token_internal_weak_stubs.c`
- `stack/internal/src/stubs/sl_zigbee_zdo_security_internal_weak_stubs.c`
- `stack/internal/src/stubs/stack-info-internal-weak-stubs.c`
- `stack/mac/mac-info-element-parsing-stub.c`
- `stack/platform/sl_zigbee_token_legacy.c`
- `stack/routing/zigbee/enhanced-beacon-request-stub.c`
- `stack/security/cbke-crypto-engine-163k1-stub.c`
- `stack/security/cbke-crypto-engine-283k1-stub.c`
- `stack/security/cbke-crypto-engine-dsa-sign-stub.c`
- `stack/security/cbke-crypto-engine-dsa-verify-283k1-stub.c`
- `stack/security/cbke-crypto-engine-dsa-verify-stub.c`
- `stack/security/cbke-crypto-engine-stub.c`
- `stack/security/security-address-cache.c`
- `stack/stubs/sl_zigbee_dynamic_commissioning_stubs.c`
- `stack/stubs/sl_zigbee_fragmentation_stubs.c`
- `stack/stubs/sl_zigbee_r23_misc_support_stubs.c`
- `stack/stubs/sli_zigbee_zdo_cluster_filter_stubs.c`
- `stack/zigbee/aps-keys-full-stub.c`
- `stack/zigbee/zdo-r22-stub.c`

### `zigbee_strong_random_api_psa`

- `stack/framework/strong-random-api.c`

### `zigbee_system_common`

- `app/framework/common/sl_zigbee_system_common.c`
- `app/framework/common/zigbee_app_framework_stack_cb.c`
- `app/framework/common/zigbee_stack_sleep.c`
- `app/util/security/security.h`

### `zigbee_system_common_app_framework`

- `app/framework/common/zigbee_app_framework_sleep.c`

### `zigbee_update_tc_link_key`

- `app/framework/plugin/update-tc-link-key/update-tc-link-key-cb.c`
- `app/framework/plugin/update-tc-link-key/update-tc-link-key.c`

### `zigbee_zcl_cli`

- `app/framework/plugin/zcl_cli/zigbee-zcl-custom-cluster-cli.c`
- `app/framework/plugin/zcl_cli/zigbee-zcl-global-cli.c`

### `zigbee_zcl_framework_core`

- `app/framework/security/af-node.c`
- `app/framework/security/af-security-common.c`
- `app/framework/security/af-trust-center.c`
- `app/framework/security/crypto-state.c`
- `app/framework/util/af-common.c`
- `app/framework/util/af-event.c`
- `app/framework/util/af-soc-common.c`
- `app/framework/util/af-soc.c`
- `app/framework/util/attribute-size.c`
- `app/framework/util/attribute-storage.c`
- `app/framework/util/attribute-table.c`
- `app/framework/util/client-api.c`
- `app/framework/util/global-callback.c`
- `app/framework/util/global-other-callback.c`
- `app/framework/util/message.c`
- `app/framework/util/multi-network.c`
- `app/framework/util/print-formatter.c`
- `app/framework/util/print.c`
- `app/framework/util/process-cluster-message.c`
- `app/framework/util/process-global-message.c`
- `app/framework/util/service-discovery-common.c`
- `app/framework/util/service-discovery-soc.c`
- `app/framework/util/time-util.c`
- `app/framework/util/util.c`
- `app/framework/util/zcl-util.c`
- `app/util/common/library.c`
- `app/util/zigbee-framework/zigbee-device-common.c`
- `app/util/zigbee-framework/zigbee-device-library.c`

### `zigbee_zll_commissioning_common`

- `app/framework/plugin/zll-commissioning-common/zll-commissioning-common-cb.c`
- `app/framework/plugin/zll-commissioning-common/zll-commissioning-common.c`

### `zigbee_zll_commissioning_server`

- `app/framework/plugin/zll-commissioning-server/zll-commissioning-server-cb.c`
- `app/framework/plugin/zll-commissioning-server/zll-commissioning-server.c`

### `zigbee_zll_identify_server`

- `app/framework/plugin/zll-identify-server/zll-identify-server.c`

### `zigbee_zll_level_control_server`

- `app/framework/plugin/zll-level-control-server/zll-level-control-server.c`

### `zigbee_zll_on_off_server`

- `app/framework/plugin/zll-on-off-server/zll-on-off-server-cb.c`
- `app/framework/plugin/zll-on-off-server/zll-on-off-server.c`

### `zigbee_zll_scenes_server`

- `app/framework/plugin/zll-scenes-server/zll-scenes-server.c`

### `zigbee_zll_utility_server`

- `app/framework/plugin/zll-utility-server/zll-utility-server.c`

## Skipped Or Inactive Conditional Entries

- `zigbee_core_cli` `source` `app/framework/cli/core-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_counters` `source` `app/framework/plugin/counters/counters-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_counters` `source` `app/framework/plugin/counters/counters-ota-host.c` (condition: `zigbee_ezsp`, unless: `-`)
- `zigbee_find_and_bind_target` `source` `app/framework/plugin/find-and-bind-target/find-and-bind-target-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_gp` `source` `app/em260/command-handlers-green-power-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_gp` `source` `stack/internal/src/ipc/gp-types-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_gp` `source` `stack/internal/src/ipc/zigbee_ipc_callback_event_stub.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_gp` `source` `stack/internal/src/ipc/gp-proxy-table-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_gp` `source` `stack/internal/src/ipc/zigbee_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_gp` `source` `stack/internal/src/ipc/gp-sink-table-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_gp` `include` `stack/internal/src/ipc` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_green_power_client_cli` `source` `app/framework/plugin/green-power-client/green-power-client-cli.c` (condition: `cli, zigbee_green_power_client`, unless: `-`)
- `zigbee_green_power_client_cli` `source` `app/framework/plugin/green-power-client/green-power-client.c` (condition: `cli, zigbee_green_power_client`, unless: `-`)
- `zigbee_green_power_client_cli` `source` `app/framework/plugin/green-power-common/green-power-cli.c` (condition: `cli`, unless: `zigbee_green_power_client`)
- `zigbee_green_power_common` `source` `stack/gp/gp-util.c` (condition: `zigbee_ezsp`, unless: `-`)
- `zigbee_groups_server` `source` `app/framework/plugin/groups-server/groups-server-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_identify` `source` `app/framework/plugin/identify/identify-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_interpan` `source` `app/framework/plugin/interpan/interpan-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_interpan` `source` `app/framework/plugin/interpan/interpan-host.c` (condition: `zigbee_ezsp`, unless: `-`)
- `zigbee_network_creator` `source` `app/framework/plugin/network-creator/network-creator-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_network_creator_security` `source` `app/framework/plugin/network-creator-security/network-creator-security-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_network_steering` `source` `app/framework/plugin/network-steering/network-steering-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_reporting` `source` `app/framework/plugin/reporting/reporting-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_scenes` `source` `app/framework/plugin/scenes/scenes-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_security_manager` `source` `stack/internal/src/ipc/security_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_security_manager` `source` `stack/internal/src/ipc/security_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_security_manager` `source` `stack/internal/src/ipc/zigbee_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_security_manager` `source` `stack/internal/src/ipc/zigbee_ipc_callback_event_stub.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_security_manager` `source` `stack/internal/src/ipc/aes-mmo-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_security_manager` `source` `stack/internal/src/ipc/zigbee-security-manager-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_security_manager` `include` `stack/internal/src/ipc` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_source_route` `source` `stack/internal/src/ipc/source-route-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_source_route` `source` `stack/internal/src/ipc/zigbee_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_source_route` `source` `stack/internal/src/ipc/zigbee_ipc_callback_event_stub.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_source_route` `include` `stack/internal/src/ipc` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `app/em260/command-handlers-binding-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/zigbee_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/binding-table-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/binding-table-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/zigbee_ipc_callback_event_stub.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `app/em260/command-handlers-messaging-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `source` `app/em260/command-handlers-networking-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `source` `app/em260/command-handlers-security-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `source` `app/em260/command-handlers-trust-center-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `source` `app/em260/command-handlers-configuration-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `source` `stack/framework/debug-stub.c` (condition: `-`, unless: `zigbee_debug_basic`)
- `zigbee_stack_common` `source` `stack/gp/gp-stub.c` (condition: `-`, unless: `zigbee_gp`)
- `zigbee_stack_common` `source` `stack/zll/zll-stubs.c` (condition: `-`, unless: `zigbee_zll`)
- `zigbee_stack_common` `source` `stack/zigbee/source-route-stub.c` (condition: `-`, unless: `zigbee_source_route`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/sl_zigbee_token_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/platform/sl_zigbee_token.c` (condition: `-`, unless: `device_series_2`)
- `zigbee_stack_common` `source` `stack/platform/sl_zigbee_token_defines.c` (condition: `-`, unless: `device_series_2`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/child_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/raw-message-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/stack-info-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/stack-info-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/network-formation-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/zigbee-device-stack-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/mac-layer-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/multi-phy-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/trust-center-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/trust-center-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/raw-message-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/message_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/library_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/network-formation-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/message_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/bootload_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/bootload_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/child_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/sl_zigbee_duty_cycle_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/sl_zigbee_duty_cycle_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/raw-message-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/security_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/sl_zigbee_random_api_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `source` `stack/internal/src/ipc/sl_zigbee_address_info_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `app/em260/command-handlers-zll.h` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `include_file` `app/em260/command-handlers-binding.h` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `include_file` `app/em260/command-handlers-security.h` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `include_file` `app/em260/command-handlers-zigbee-pro.h` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/bootload_ipc_callback_events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/bootload_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/child_ipc_callback_events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/child_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/sl_zigbee_duty_cycle_ipc_callback_events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/message_ipc_callback_events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/network-formation-ipc-callback-events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/raw-message-ipc-callback-events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/security_ipc_callback_events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/stack-info-ipc-callback-events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/sl_zigbee_duty_cycle_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/sl_zigbee_random_api_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/library_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/mac-layer-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/message_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/mfglib_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/multi-network-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/multi-phy-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/network-formation-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/raw-message-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/security_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/sl_zigbee_address_info_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/stack-info-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/trust-center-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/zigbee-device-stack-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/zigbee-security-manager-ipc-command-messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/trust-center-ipc-callback-events.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include_file` `stack/internal/src/ipc/sl_zigbee_token_ipc_command_messages.h` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include` `stack/internal/src/ipc` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_common` `include` `stack/internal/src/ipc` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_stack_diagnostics` `source` `app/framework/plugin/stack-diagnostics/stack-diagnostics.c` (condition: `cli`, unless: `-`)
- `zigbee_system_common` `source` `app/framework/common/zigbee_app_framework_stack_cb.c` (condition: `native_host`, unless: `-`)
- `zigbee_system_common` `source` `app/framework/common/zigbee_stack_rtos_adaptation.c` (condition: `cmsis_rtos2`, unless: `-`)
- `zigbee_system_common` `source` `stack/internal/src/ipc/zigbee_ipc_callback_event_stub.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_system_common` `source` `stack/internal/src/ipc/security_ipc_command_messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_system_common` `source` `stack/internal/src/ipc/security_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_system_common` `source` `stack/internal/src/ipc/zigbee_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_system_common` `include` `app/framework/common` (condition: `cmsis_rtos2`, unless: `-`)
- `zigbee_system_common` `include` `app/framework/common` (condition: `cmsis_rtos2`, unless: `-`)
- `zigbee_system_common` `include` `stack/internal/src/ipc` (condition: `cmsis_rtos2`, unless: `-`)
- `zigbee_system_common_app_framework` `source` `app/framework/common/zigbee_app_framework_sleep_cli.c` (condition: `cli`, unless: `-`)
- `zigbee_system_common_app_framework` `source` `app/framework/common/zigbee_app_framework_rtos_adaptation.c` (condition: `cmsis_rtos2`, unless: `-`)
- `zigbee_update_tc_link_key` `source` `app/framework/plugin/update-tc-link-key/update-tc-link-key-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_cli` `source` `app/framework/plugin/zcl_cli/zigbee-zcl-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/cli/core-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/cli/network-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/cli/option-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/cli/security-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/cli/zcl-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/cli/zdo-cli.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/util/serial/sl_zigbee_command_interpreter.c` (condition: `cli`, unless: `-`)
- `zigbee_zcl_framework_core` `source` `app/framework/plugin/zcl-framework-core/zcl-framework-core-cb.c` (condition: `zigbee_ezsp`, unless: `-`)
- `zigbee_zcl_framework_core` `include` `app/util/ezsp` (condition: `zigbee_ezsp`, unless: `-`)
- `zigbee_zcl_framework_core` `include` `app/framework/plugin/zcl-framework-core` (condition: `zigbee_ezsp`, unless: `-`)
- `zigbee_zcl_framework_core` `include` `app/framework/cli` (condition: `cli`, unless: `-`)
- `zigbee_zll` `source` `app/em260/command-handlers-zll-generated.c` (condition: `zigbee_ncp`, unless: `-`)
- `zigbee_zll` `source` `stack/internal/src/ipc/zigbee_ipc_callback_event_stub.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_zll` `source` `stack/internal/src/ipc/zll-api-ipc-callback-events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_zll` `source` `stack/internal/src/ipc/zll-api-ipc-command-messages.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_zll` `source` `stack/internal/src/ipc/zigbee_ipc_callback_events.c` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_zll` `include` `stack/internal/src/ipc` (condition: `zigbee_use_ipc`, unless: `-`)
- `zigbee_zll_commissioning_common` `source` `app/framework/plugin/zll-commissioning-common/zll-commissioning-cli.c` (condition: `cli`, unless: `-`)
