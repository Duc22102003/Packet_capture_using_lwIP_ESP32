#include "wifi_manager.h"
#include "packet_capture.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include <string.h>

#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

static EventGroupHandle_t s_wifi_event_group;
static esp_netif_t *s_netif = NULL;
static int s_retry_num = 0;
static bool s_capture_enabled = false;

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();

    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < 10) {
            esp_wifi_connect();
            s_retry_num++;
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

        // HOOK PACKET CAPTURE SAU KHI ĐÃ KẾT NỐI
        if (s_capture_enabled) {
            packet_capture_install_hook(s_netif);
        }
    }
}

esp_err_t wifi_manager_init(const char *ssid, const char *password,
                            bool enable_capture)
{
    s_capture_enabled = enable_capture;
    
    // Khởi tạo TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    s_wifi_event_group = xEventGroupCreate();
    
    // Tạo netif
    s_netif = esp_netif_create_default_wifi_sta();
    if (!s_netif) {
        return ESP_FAIL;
    }

    // Khởi tạo WiFi driver
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, 
                                               ESP_EVENT_ANY_ID, 
                                               &wifi_event_handler, 
                                               NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, 
                                               IP_EVENT_STA_GOT_IP, 
                                               &wifi_event_handler, 
                                               NULL));
    
    // Cấu hình WiFi
    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    
    strncpy((char *)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    
    // [6] Start WiFi
    ESP_ERROR_CHECK(esp_wifi_start());
    
    return ESP_OK;
}

esp_netif_t* wifi_manager_get_netif(void)
{
    return s_netif;
}

bool wifi_manager_wait_connected(uint32_t timeout_ms)
{
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,
        pdFALSE,
        timeout_ms == 0 ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms)
    );
    
    if (bits & WIFI_CONNECTED_BIT) {
        return true;
    } else if (bits & WIFI_FAIL_BIT) {
        return false;
    } else {
        return false;
    }
}

esp_err_t wifi_manager_get_ip(char *ip_str, size_t len)
{
    if (!s_netif || !ip_str || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    esp_netif_ip_info_t ip_info;
    esp_err_t ret = esp_netif_get_ip_info(s_netif, &ip_info);
    
    if (ret == ESP_OK) {
        snprintf(ip_str, len, IPSTR, IP2STR(&ip_info.ip));
    }
    
    return ret;
}
