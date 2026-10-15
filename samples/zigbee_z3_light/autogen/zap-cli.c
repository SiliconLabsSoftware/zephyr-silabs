/***************************************************************************//**
 * @file  zap-cli.c
 * @brief Generated file for zcl cli using ZAP. Do not update file manually.
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

#ifdef SL_COMPONENT_CATALOG_PRESENT
#include "sl_component_catalog.h"
#endif

#ifdef SL_CATALOG_ZIGBEE_ZCL_CLI_PRESENT

#include <stdlib.h>
#include "sl_cli_config.h"
#include "sl_cli_command.h"
#include "sl_cli.h"
#include "zcl-cli.h"
#ifdef SL_CATALOG_ZIGBEE_DEBUG_PRINT_PRESENT
#include "sl_zigbee_debug_print.h"
#endif // SL_CATALOG_ZIGBEE_DEBUG_PRINT_PRESENT
#include "zap-type.h"
#include "zap-id.h"
#include "app/framework/include/af.h"
#include "zap-config.h"

extern void sli_zigbee_zcl_simple_command(uint8_t frameControl,
                        uint16_t clusterId,
                        uint8_t commandId,
                        sl_cli_command_arg_t *arguments,
                        uint8_t *argumentTypes);
extern sl_cli_command_info_t cli_cmd_zcl_global_group;
extern sl_cli_command_info_t cli_cmd_zcl_mfg_code_command;
extern sl_cli_command_info_t cli_cmd_zcl_time_command;
extern sl_cli_command_info_t cli_cmd_zcl_use_next_sequence_command;
extern sl_cli_command_info_t cli_cmd_zcl_x_default_resp_command;
extern sl_cli_command_info_t cli_cmd_zcl_test_response_on_command;
extern sl_cli_command_info_t cli_cmd_zcl_test_response_off_command;
#if defined(ZCL_USING_IDENTIFY_CLUSTER_SERVER) || defined(ZCL_USING_IDENTIFY_CLUSTER_CLIENT)
extern sl_cli_command_info_t cli_cmd_zcl_identify_on_command;
extern sl_cli_command_info_t cli_cmd_zcl_identify_off_command;
#endif
#if defined(ZCL_USING_BACNET_PROTOCOL_TUNNEL_CLUSTER_CLIENT) || defined(ZCL_USING_BACNET_PROTOCOL_TUNNEL_CLUSTER_SERVER)
extern sl_cli_command_info_t cli_cmd_zcl_bacnet_transfer_whois_command;
#endif
#if defined(ZCL_USING_TUNNELING_CLUSTER_CLIENT) || defined(ZCL_USING_TUNNELING_CLUSTER_SERVER)
extern sl_cli_command_info_t cli_cmd_zcl_tunneling_random_to_server_command;
extern sl_cli_command_info_t cli_cmd_zcl_tunneling_transfer_to_server_command;
extern sl_cli_command_info_t cli_cmd_zcl_tunneling_random_to_client_command;
extern sl_cli_command_info_t cli_cmd_zcl_tunneling_transfer_to_client_command;
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Provide function declarations
void sli_zigbee_cli_zcl_groups_add_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_groups_add_if_id_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_add_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_loop_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_copy_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_identify_ez_mode_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_eadd_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_emovehue_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_emovetohue_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_emovetohueandsat_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_estephue_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_eview_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_groups_get_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_get_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_identify_id_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_identify_query_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_move_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movecolor_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movecolortemp_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movehue_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movesat_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movetocolor_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movetocolortemp_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movetohue_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movetohueandsat_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_mv_to_level_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_o_mv_to_level_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_movetosat_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_o_move_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_on_off_off_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_on_off_offeffect_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_on_off_on_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_on_off_onrecall_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_on_off_ontimedoff_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_recall_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_groups_rmall_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_rmall_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_groups_remove_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_remove_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_basic_rtfd_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_step_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_stepcolor_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_stepcolortemp_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_stephue_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_stepsat_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_o_step_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_stop_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_color_control_stopmovestep_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_level_control_o_stop_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_store_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_on_off_toggle_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_identify_trigger_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_groups_view_command(sl_cli_command_arg_t *arguments);
void sli_zigbee_cli_zcl_scenes_view_command(sl_cli_command_arg_t *arguments);

// Command structs. Names are command names prefixed by cli_cmd_zcl_[cluster name]_cluster
static const sl_cli_command_info_t cli_cmd_zcl_groups_cluster_add_group = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_groups_add_command,
            "Command description for AddGroup",
            "group id" SL_CLI_UNIT_SEPARATOR "group name" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_STRING,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_groups_cluster_add_group_if_identifying = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_groups_add_if_id_command,
            "Command description for AddGroupIfIdentifying",
            "group id" SL_CLI_UNIT_SEPARATOR "group name" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_STRING,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_add_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_add_command,
            "Add a scene to the scene table. Extension field sets are supported, and are inputed as arrays of the form [[cluster ID] [length] [value0...n] ...]",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "scene name" SL_CLI_UNIT_SEPARATOR "extension field sets" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_STRING,
                SL_CLI_ARG_HEXOPT,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_color_loop_set = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_loop_command,
            "Command description for ColorLoopSet",
            "update flags" SL_CLI_UNIT_SEPARATOR "action" SL_CLI_UNIT_SEPARATOR "direction" SL_CLI_UNIT_SEPARATOR "time" SL_CLI_UNIT_SEPARATOR "start hue" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_copy_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_copy_command,
            "Command description for CopyScene",
            "mode" SL_CLI_UNIT_SEPARATOR "group id from" SL_CLI_UNIT_SEPARATOR "scene id from" SL_CLI_UNIT_SEPARATOR "group id to" SL_CLI_UNIT_SEPARATOR "scene id to" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_identify_cluster_ez_mode_invoke = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_identify_ez_mode_command,
            "Invoke EZMode on an Identify Server",
            "action" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_enhanced_add_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_eadd_command,
            "Command description for EnhancedAddScene",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "scene name" SL_CLI_UNIT_SEPARATOR "extension field sets" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_STRING,
                SL_CLI_ARG_HEXOPT,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_enhanced_move_hue = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_emovehue_command,
            "Command description for EnhancedMoveHue",
            "move mode" SL_CLI_UNIT_SEPARATOR "rate" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_enhanced_move_to_hue = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_emovetohue_command,
            "Command description for EnhancedMoveToHue",
            "enhanced hue" SL_CLI_UNIT_SEPARATOR "direction" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_enhanced_move_to_hue_and_saturation = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_emovetohueandsat_command,
            "Command description for EnhancedMoveToHueAndSaturation",
            "enhanced hue" SL_CLI_UNIT_SEPARATOR "saturation" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_enhanced_step_hue = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_estephue_command,
            "Command description for EnhancedStepHue",
            "step mode" SL_CLI_UNIT_SEPARATOR "step size" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_enhanced_view_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_eview_command,
            "Command description for EnhancedViewScene",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_groups_cluster_get_group_membership = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_groups_get_command,
            "Command description for GetGroupMembership",
            "group count" SL_CLI_UNIT_SEPARATOR "group list" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16OPT,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_get_scene_membership = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_get_command,
            "Command description for GetSceneMembership",
            "group id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_identify_cluster_identify = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_identify_id_command,
            "Command description for Identify",
            "identify time" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_identify_cluster_identify_query = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_identify_query_command,
            "Command description for IdentifyQuery",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_move = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_move_command,
            "Command description for Move",
            "move mode" SL_CLI_UNIT_SEPARATOR "rate" SL_CLI_UNIT_SEPARATOR "option mask" SL_CLI_UNIT_SEPARATOR "option override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_color = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movecolor_command,
            "Moves the color.",
            "ratex" SL_CLI_UNIT_SEPARATOR "ratey" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_INT16,
                SL_CLI_ARG_INT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_color_temperature = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movecolortemp_command,
            "Command description for MoveColorTemperature",
            "move mode" SL_CLI_UNIT_SEPARATOR "rate" SL_CLI_UNIT_SEPARATOR "color temperature minimum" SL_CLI_UNIT_SEPARATOR "color temperature maximum" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_hue = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movehue_command,
            "Move hue up or down at specified rate.",
            "move mode" SL_CLI_UNIT_SEPARATOR "rate" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_saturation = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movesat_command,
            "Move saturation up or down at specified rate.",
            "move mode" SL_CLI_UNIT_SEPARATOR "rate" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_to_color = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movetocolor_command,
            "Move to specified color.",
            "colorx" SL_CLI_UNIT_SEPARATOR "colory" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_to_color_temperature = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movetocolortemp_command,
            "Move to a specific color temperature.",
            "color temperature" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_to_hue = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movetohue_command,
            "Move to specified hue.",
            "hue" SL_CLI_UNIT_SEPARATOR "direction" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_to_hue_and_saturation = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movetohueandsat_command,
            "Move to hue and saturation.",
            "hue" SL_CLI_UNIT_SEPARATOR "saturation" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_move_to_level = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_mv_to_level_command,
            "Command description for MoveToLevel",
            "level" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "option mask" SL_CLI_UNIT_SEPARATOR "option override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_move_to_level_with_on_off = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_o_mv_to_level_command,
            "Command description for MoveToLevelWithOnOff",
            "level" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_move_to_saturation = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_movetosat_command,
            "Move to specified saturation.",
            "saturation" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_move_with_on_off = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_o_move_command,
            "Command description for MoveWithOnOff",
            "move mode" SL_CLI_UNIT_SEPARATOR "rate" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_on_off_cluster_off = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_on_off_off_command,
            "Command description for Off",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_on_off_cluster_off_with_effect = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_on_off_offeffect_command,
            "Command description for OffWithEffect",
            "effect id" SL_CLI_UNIT_SEPARATOR "effect variant" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_on_off_cluster_on = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_on_off_on_command,
            "Command description for On",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_on_off_cluster_on_with_recall_global_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_on_off_onrecall_command,
            "Command description for OnWithRecallGlobalScene",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_on_off_cluster_on_with_timed_off = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_on_off_ontimedoff_command,
            "Command description for OnWithTimedOff",
            "on off control" SL_CLI_UNIT_SEPARATOR "on time" SL_CLI_UNIT_SEPARATOR "off wait time" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_recall_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_recall_command,
            "Command description for RecallScene",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_groups_cluster_remove_all_groups = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_groups_rmall_command,
            "Command description for RemoveAllGroups",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_remove_all_scenes = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_rmall_command,
            "Command description for RemoveAllScenes",
            "group id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_groups_cluster_remove_group = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_groups_remove_command,
            "Command description for RemoveGroup",
            "group id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_remove_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_remove_command,
            "Command description for RemoveScene",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_basic_cluster_reset_to_factory_defaults = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_basic_rtfd_command,
            "Command that resets all attribute values to factory default.",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_step = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_step_command,
            "Command description for Step",
            "step mode" SL_CLI_UNIT_SEPARATOR "step size" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "option mask" SL_CLI_UNIT_SEPARATOR "option override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_step_color = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_stepcolor_command,
            "Steps the lighting to a specific color.",
            "stepx" SL_CLI_UNIT_SEPARATOR "stepy" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_INT16,
                SL_CLI_ARG_INT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_step_color_temperature = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_stepcolortemp_command,
            "Command description for StepColorTemperature",
            "step mode" SL_CLI_UNIT_SEPARATOR "step size" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "color temperature minimum" SL_CLI_UNIT_SEPARATOR "color temperature maximum" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_step_hue = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_stephue_command,
            "Step hue up or down by specified size at specified rate.",
            "step mode" SL_CLI_UNIT_SEPARATOR "step size" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_step_saturation = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_stepsat_command,
            "Step saturation up or down by specified size at specified rate.",
            "step mode" SL_CLI_UNIT_SEPARATOR "step size" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_step_with_on_off = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_o_step_command,
            "Command description for StepWithOnOff",
            "step mode" SL_CLI_UNIT_SEPARATOR "step size" SL_CLI_UNIT_SEPARATOR "transition time" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_stop = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_stop_command,
            "Command description for Stop",
            "option mask" SL_CLI_UNIT_SEPARATOR "option override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_color_control_cluster_stop_move_step = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_color_control_stopmovestep_command,
            "Command description for StopMoveStep",
            "options mask" SL_CLI_UNIT_SEPARATOR "options override" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_level_control_cluster_stop_with_on_off = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_level_control_o_stop_command,
            "Command description for StopWithOnOff",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_store_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_store_command,
            "Command description for StoreScene",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_on_off_cluster_toggle = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_on_off_toggle_command,
            "Command description for Toggle",
            "",
            {
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_identify_cluster_trigger_effect = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_identify_trigger_command,
            "Command description for TriggerEffect",
            "effect id" SL_CLI_UNIT_SEPARATOR "effect variant" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_groups_cluster_view_group = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_groups_view_command,
            "Command description for ViewGroup",
            "group id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_END,
            });

static const sl_cli_command_info_t cli_cmd_zcl_scenes_cluster_view_scene = \
SL_CLI_COMMAND(sli_zigbee_cli_zcl_scenes_view_command,
            "Command description for ViewScene",
            "group id" SL_CLI_UNIT_SEPARATOR "scene id" SL_CLI_UNIT_SEPARATOR ,
            {
                SL_CLI_ARG_UINT16,
                SL_CLI_ARG_UINT8,
                SL_CLI_ARG_END,
            });


// Create group command tables and structs if cli_groups given
// in template. Group name is suffixed with [cluster name]_[cluster_side]_cluster_group_table for tables
// and group commands are cli_cmd_( group name )_group
static const sl_cli_command_entry_t zcl_basic_cluster_command_table[] = {
    { "rtfd", &cli_cmd_zcl_basic_cluster_reset_to_factory_defaults, false },
    { NULL, NULL, false },
};
static const sl_cli_command_entry_t zcl_color_control_cluster_command_table[] = {
    { "movetohue", &cli_cmd_zcl_color_control_cluster_move_to_hue, false },
    { "movehue", &cli_cmd_zcl_color_control_cluster_move_hue, false },
    { "stephue", &cli_cmd_zcl_color_control_cluster_step_hue, false },
    { "movetosat", &cli_cmd_zcl_color_control_cluster_move_to_saturation, false },
    { "movesat", &cli_cmd_zcl_color_control_cluster_move_saturation, false },
    { "stepsat", &cli_cmd_zcl_color_control_cluster_step_saturation, false },
    { "movetohueandsat", &cli_cmd_zcl_color_control_cluster_move_to_hue_and_saturation, false },
    { "movetocolor", &cli_cmd_zcl_color_control_cluster_move_to_color, false },
    { "movecolor", &cli_cmd_zcl_color_control_cluster_move_color, false },
    { "stepcolor", &cli_cmd_zcl_color_control_cluster_step_color, false },
    { "movetocolortemp", &cli_cmd_zcl_color_control_cluster_move_to_color_temperature, false },
    { "emovetohue", &cli_cmd_zcl_color_control_cluster_enhanced_move_to_hue, false },
    { "emovehue", &cli_cmd_zcl_color_control_cluster_enhanced_move_hue, false },
    { "estephue", &cli_cmd_zcl_color_control_cluster_enhanced_step_hue, false },
    { "emovetohueandsat", &cli_cmd_zcl_color_control_cluster_enhanced_move_to_hue_and_saturation, false },
    { "loop", &cli_cmd_zcl_color_control_cluster_color_loop_set, false },
    { "stopmovestep", &cli_cmd_zcl_color_control_cluster_stop_move_step, false },
    { "movecolortemp", &cli_cmd_zcl_color_control_cluster_move_color_temperature, false },
    { "stepcolortemp", &cli_cmd_zcl_color_control_cluster_step_color_temperature, false },
    { NULL, NULL, false },
};
static const sl_cli_command_entry_t zcl_groups_cluster_command_table[] = {
    { "add", &cli_cmd_zcl_groups_cluster_add_group, false },
    { "view", &cli_cmd_zcl_groups_cluster_view_group, false },
    { "get", &cli_cmd_zcl_groups_cluster_get_group_membership, false },
    { "remove", &cli_cmd_zcl_groups_cluster_remove_group, false },
    { "rmall", &cli_cmd_zcl_groups_cluster_remove_all_groups, false },
    { "add-if-id", &cli_cmd_zcl_groups_cluster_add_group_if_identifying, false },
    { NULL, NULL, false },
};
static const sl_cli_command_entry_t zcl_identify_cluster_command_table[] = {
    { "id", &cli_cmd_zcl_identify_cluster_identify, false },
    { "query", &cli_cmd_zcl_identify_cluster_identify_query, false },
    { "ez-mode", &cli_cmd_zcl_identify_cluster_ez_mode_invoke, false },
    { "trigger", &cli_cmd_zcl_identify_cluster_trigger_effect, false },
    { "on", &cli_cmd_zcl_identify_on_command, false},
    { "off", &cli_cmd_zcl_identify_off_command, false},
    { NULL, NULL, false },
};
static const sl_cli_command_entry_t zcl_level_control_cluster_command_table[] = {
    { "mv-to-level", &cli_cmd_zcl_level_control_cluster_move_to_level, false },
    { "move", &cli_cmd_zcl_level_control_cluster_move, false },
    { "step", &cli_cmd_zcl_level_control_cluster_step, false },
    { "stop", &cli_cmd_zcl_level_control_cluster_stop, false },
    { "o-mv-to-level", &cli_cmd_zcl_level_control_cluster_move_to_level_with_on_off, false },
    { "o-move", &cli_cmd_zcl_level_control_cluster_move_with_on_off, false },
    { "o-step", &cli_cmd_zcl_level_control_cluster_step_with_on_off, false },
    { "o-stop", &cli_cmd_zcl_level_control_cluster_stop_with_on_off, false },
    { NULL, NULL, false },
};
static const sl_cli_command_entry_t zcl_on_off_cluster_command_table[] = {
    { "off", &cli_cmd_zcl_on_off_cluster_off, false },
    { "on", &cli_cmd_zcl_on_off_cluster_on, false },
    { "toggle", &cli_cmd_zcl_on_off_cluster_toggle, false },
    { "offeffect", &cli_cmd_zcl_on_off_cluster_off_with_effect, false },
    { "onrecall", &cli_cmd_zcl_on_off_cluster_on_with_recall_global_scene, false },
    { "ontimedoff", &cli_cmd_zcl_on_off_cluster_on_with_timed_off, false },
    { NULL, NULL, false },
};
static const sl_cli_command_entry_t zcl_scenes_cluster_command_table[] = {
    { "add", &cli_cmd_zcl_scenes_cluster_add_scene, false },
    { "view", &cli_cmd_zcl_scenes_cluster_view_scene, false },
    { "remove", &cli_cmd_zcl_scenes_cluster_remove_scene, false },
    { "rmall", &cli_cmd_zcl_scenes_cluster_remove_all_scenes, false },
    { "store", &cli_cmd_zcl_scenes_cluster_store_scene, false },
    { "recall", &cli_cmd_zcl_scenes_cluster_recall_scene, false },
    { "get", &cli_cmd_zcl_scenes_cluster_get_scene_membership, false },
    { "eadd", &cli_cmd_zcl_scenes_cluster_enhanced_add_scene, false },
    { "eview", &cli_cmd_zcl_scenes_cluster_enhanced_view_scene, false },
    { "copy", &cli_cmd_zcl_scenes_cluster_copy_scene, false },
    { NULL, NULL, false },
};

// ZCL cluster commands
static const sl_cli_command_info_t cli_cmd_basic_group = \
  SL_CLI_COMMAND_GROUP(zcl_basic_cluster_command_table, "ZCL basic cluster commands");
static const sl_cli_command_info_t cli_cmd_color_control_group = \
  SL_CLI_COMMAND_GROUP(zcl_color_control_cluster_command_table, "ZCL color_control cluster commands");
static const sl_cli_command_info_t cli_cmd_groups_group = \
  SL_CLI_COMMAND_GROUP(zcl_groups_cluster_command_table, "ZCL groups cluster commands");
static const sl_cli_command_info_t cli_cmd_identify_group = \
  SL_CLI_COMMAND_GROUP(zcl_identify_cluster_command_table, "ZCL identify cluster commands");
static const sl_cli_command_info_t cli_cmd_level_control_group = \
  SL_CLI_COMMAND_GROUP(zcl_level_control_cluster_command_table, "ZCL level_control cluster commands");
static const sl_cli_command_info_t cli_cmd_on_off_group = \
  SL_CLI_COMMAND_GROUP(zcl_on_off_cluster_command_table, "ZCL on_off cluster commands");
static const sl_cli_command_info_t cli_cmd_scenes_group = \
  SL_CLI_COMMAND_GROUP(zcl_scenes_cluster_command_table, "ZCL scenes cluster commands");

static const sl_cli_command_entry_t zcl_group_table[] = {
  { "basic", &cli_cmd_basic_group, false },
  { "color-control", &cli_cmd_color_control_group, false },
  { "groups", &cli_cmd_groups_group, false },
  { "identify", &cli_cmd_identify_group, false },
  { "level-control", &cli_cmd_level_control_group, false },
  { "on-off", &cli_cmd_on_off_group, false },
  { "scenes", &cli_cmd_scenes_group, false },
  { "global", &cli_cmd_zcl_global_group, false },
  { "mfg-code", &cli_cmd_zcl_mfg_code_command, false},
  { "time", &cli_cmd_zcl_time_command, false},
  { "use-next-sequence", &cli_cmd_zcl_use_next_sequence_command, false},
  { "x-default-resp", &cli_cmd_zcl_x_default_resp_command, false},
  { "test-response-on", &cli_cmd_zcl_test_response_on_command, false},
  { "test-response-off", &cli_cmd_zcl_test_response_off_command, false},
  { NULL, NULL, false },
};

sl_cli_command_info_t cli_cmd_zcl_group = \
  SL_CLI_COMMAND_GROUP(zcl_group_table, "ZCL commands");

// Create root command table
const sl_cli_command_entry_t sl_cli_zcl_command_table[] = {
  { "zcl", &cli_cmd_zcl_group, false },
  { NULL, NULL, false },
};

sl_cli_command_group_t sl_cli_zcl_command_group =
{
  { NULL },
  false,
  sl_cli_zcl_command_table
};


WEAK(void sli_zigbee_cli_zcl_groups_add_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_STRING
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_GROUPS_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_groups_add_if_id_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_STRING
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_GROUPS_CLUSTER_ID,                                                       \
    5, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_add_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_STRING,
    SL_ZCL_CLI_ARG_HEXOPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_loop_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[7] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    68, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_copy_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    66, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_identify_ez_mode_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[1] =  { 
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_IDENTIFY_CLUSTER_ID,                                                       \
    2, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_eadd_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_STRING,
    SL_ZCL_CLI_ARG_HEXOPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    64, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_emovehue_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    65, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_emovetohue_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    64, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_emovetohueandsat_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    67, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_estephue_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    66, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_eview_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    65, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_groups_get_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_GROUPS_CLUSTER_ID,                                                       \
    2, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_get_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[1] =  { 
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    6, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_identify_id_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[1] =  { 
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_IDENTIFY_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_identify_query_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_IDENTIFY_CLUSTER_ID,                                                       \
    1, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_level_control_move_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    1, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movecolor_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_INT16,
    SL_ZCL_CLI_ARG_INT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    8, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movecolortemp_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[6] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    75, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movehue_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    1, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movesat_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    4, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movetocolor_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    7, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movetocolortemp_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    10, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movetohue_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movetohueandsat_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    6, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_level_control_mv_to_level_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_level_control_o_mv_to_level_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    4, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_movetosat_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[4] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    3, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_level_control_o_move_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    5, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_on_off_off_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_ON_OFF_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_on_off_offeffect_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_ON_OFF_CLUSTER_ID,                                                       \
    64, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_on_off_on_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_ON_OFF_CLUSTER_ID,                                                       \
    1, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_on_off_onrecall_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_ON_OFF_CLUSTER_ID,                                                       \
    65, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_on_off_ontimedoff_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[3] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_ON_OFF_CLUSTER_ID,                                                       \
    66, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_recall_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[3] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    5, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_groups_rmall_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_GROUPS_CLUSTER_ID,                                                       \
    4, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_scenes_rmall_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[1] =  { 
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    3, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_groups_remove_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[1] =  { 
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_GROUPS_CLUSTER_ID,                                                       \
    3, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_remove_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    2, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_basic_rtfd_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_BASIC_CLUSTER_ID,                                                       \
    0, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_level_control_step_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    2, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_stepcolor_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_INT16,
    SL_ZCL_CLI_ARG_INT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    9, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_stepcolortemp_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[7] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    76, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_stephue_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    2, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_stepsat_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[5] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    5, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_level_control_o_step_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[3] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    6, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_level_control_stop_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    3, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_color_control_stopmovestep_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8OPT,
    SL_ZCL_CLI_ARG_UINT8OPT
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_COLOR_CONTROL_CLUSTER_ID,                                                       \
    71, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_level_control_o_stop_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_LEVEL_CONTROL_CLUSTER_ID,                                                       \
    7, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_scenes_store_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    4, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_on_off_toggle_command(sl_cli_command_arg_t *arguments)) {
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_ON_OFF_CLUSTER_ID,                                                       \
    2, \
    arguments, \
    NULL);
}

WEAK(void sli_zigbee_cli_zcl_identify_trigger_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT8,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_IDENTIFY_CLUSTER_ID,                                                       \
    64, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_groups_view_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[1] =  { 
    SL_ZCL_CLI_ARG_UINT16
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_GROUPS_CLUSTER_ID,                                                       \
    1, \
    arguments, \
    argumentTypes);
}

WEAK(void sli_zigbee_cli_zcl_scenes_view_command(sl_cli_command_arg_t *arguments)) {
  uint8_t argumentTypes[2] =  { 
    SL_ZCL_CLI_ARG_UINT16,
    SL_ZCL_CLI_ARG_UINT8
  }; 
  sli_zigbee_zcl_simple_command(
    ZCL_CLUSTER_SPECIFIC_COMMAND | ZCL_FRAME_CONTROL_CLIENT_TO_SERVER,  \
    ZCL_SCENES_CLUSTER_ID,                                                       \
    1, \
    arguments, \
    argumentTypes);
}

#ifdef __cplusplus
}
#endif
#endif