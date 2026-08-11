cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ble_hid_maze)

dt_chosen(display_node PROPERTY "zephyr,display")

if(NOT DEFINED display_node)
  message(FATAL_ERROR "No zephyr,display chosen node")
endif()

dt_prop(display_width
  PATH "${display_node}"
  PROPERTY width
  REQUIRED
)

dt_prop(display_height
  PATH "${display_node}"
  PROPERTY height
  REQUIRED
)

if(display_width EQUAL 128 AND display_height EQUAL 128)
  set(background_sources
    src/bg_hex_128x128.c
    src/bg_square_128x128.c
    src/bg_triangle_128x128.c
  )
elseif(display_width EQUAL 480 AND display_height EQUAL 320)
  set(background_sources
    src/bg_hex_480x320.c
    src/bg_square_480x320.c
    src/bg_triangle_480x320.c
  )
else()
  message(FATAL_ERROR
    "No maze assets for display resolution "
    "${display_width}x${display_height}"
  )
endif()

target_sources(app PRIVATE
  src/app_graphics.c
  src/app_graphics_marker.c
  src/app_input.c
  src/app_led.c
  src/bt_connection.c
  src/hid_mouse.c
  src/main.c
  ${background_sources}
)
