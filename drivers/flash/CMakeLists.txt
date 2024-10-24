# SPDX-License-Identifier: Apache-2.0

zephyr_library_amend()
zephyr_library_sources_ifdef(CONFIG_SOC_FLASH_SILABS_SIWX917 soc_flash_silabs_siwx917.c)
