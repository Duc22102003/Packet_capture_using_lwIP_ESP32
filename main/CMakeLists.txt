idf_component_register(
    SRCS "main.c" "wifi_manager.c" "packet_capture.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_netif lwip nvs_flash esp_timer
)