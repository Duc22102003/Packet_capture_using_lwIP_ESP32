/**
 * @file packet_capture.h
 * @brief Packet capture interface
 */

#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "esp_err.h"
#include "esp_netif.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Thống kê packet
 */
typedef struct {
    uint32_t total_packets;
    uint32_t total_bytes;
    uint32_t arp_packets;
    uint32_t icmp_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t ipv6_packets;
    uint32_t other_packets;
    uint32_t queue_dropped;
} packet_stats_t;

/**
 * @brief Cấu hình packet capture
 */
typedef struct {
    uint16_t queue_size;
    bool drop_when_full;
} packet_capture_config_t;

#define PACKET_CAPTURE_DEFAULT_QUEUE_SIZE        64
#define PACKET_CAPTURE_DEFAULT_DROP_WHEN_FULL    true

/**
 * @brief Install packet capture hook
 * @param esp_netif ESP netif instance (từ esp_netif_create_default_wifi_sta)
 * @return ESP_OK nếu thành công
 */
esp_err_t packet_capture_install_hook(esp_netif_t *esp_netif);
  
esp_err_t packet_capture_install_hook_with_config(esp_netif_t *esp_netif,
                                                  const packet_capture_config_t *config);

esp_err_t packet_capture_get_stats(packet_stats_t *stats);

void packet_capture_reset_stats(void);

void packet_capture_set_enabled(bool enabled);

bool packet_capture_is_enabled(void);

#ifdef __cplusplus
}
#endif

#endif // PACKET_CAPTURE_H
