/**
 * @file wifi_manager.h
 * @brief WiFi manager interface
 */

#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_err.h"
#include "esp_netif.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Khởi tạo WiFi manager
 * @return ESP_OK nếu thành công
 */
esp_err_t wifi_manager_init(const char *ssid, const char *password,
                            bool enable_capture);

/**
 * @brief Lấy esp_netif instance
 * @return Con trỏ esp_netif/ NULL nếu chưa khởi tạo
 */
esp_netif_t* wifi_manager_get_netif(void);

/**
 * @brief Chờ WiFi kết nối
 * @return true/false
 */
bool wifi_manager_wait_connected(uint32_t timeout_ms);

/**
 * @brief Lấy IP address dạng string
 * 
 * @param ip_str Buffer để lưu IP string
 * @param len Kích thước buffer
 * @return ESP_OK nếu thành công
 */
esp_err_t wifi_manager_get_ip(char *ip_str, size_t len);

#ifdef __cplusplus
}
#endif

#endif // WIFI_MANAGER_H
