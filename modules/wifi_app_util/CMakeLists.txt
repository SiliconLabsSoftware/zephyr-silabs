add_library(wifi_app_util STATIC src/wifi_app_util.c)
target_include_directories(wifi_app_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wifi_app_util PRIVATE zephyr_interface)


