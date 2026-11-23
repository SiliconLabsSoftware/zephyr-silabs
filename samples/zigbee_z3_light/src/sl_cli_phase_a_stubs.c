/*
 * Temporary weak stubs for Studio command-table handlers compiled out
 * behind unavailable catalog symbols (rail phy select).
 */

#include "sl_cli_types.h"

__attribute__((weak)) void sli_get_pti_radio_config(sl_cli_command_arg_t *arguments)
{
	(void)arguments;
}

__attribute__((weak)) void sli_zigbee_cli_get_active_phy_command(sl_cli_command_arg_t *arguments)
{
	(void)arguments;
}
