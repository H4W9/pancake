idf_component_register(SRCS "attack_handshake.c" "ft6336.c" "lvgl_memory.c" "oui_lookup.c" "sd_error_handler.c" "gatt_walker.c" "bt_lookout.c" "ble_honeypair.c" "ble_blueduck.c" "ble_whisperpair.c" "main.c" INCLUDE_DIRS . REQUIRES heap driver esp_event console bt esp-tls PRIV_REQUIRES wifi_attacks wifi_cli wifi_scanner wifi_sniffer wifi_wardrive sniffer frame_analyzer hccapx_serializer pcap_serializer led_strip espressif__esp_lcd_ili9341)

# Disable format warning errors for ESP32-C5 (size_t is unsigned int, not long unsigned int)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=format)
