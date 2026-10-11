#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "packet_capture.h"
#include "wifi_manager.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include <unistd.h>

#define WIFI_SSID           "TP-LINK_710A"
#define WIFI_PASSWORD       "12345678"

#define TCP_SERVER_PORT     5000
#define TCP_SERVER_TASK_STACK_WORDS 4096
#define TCP_SERVER_TASK_PRIORITY    4
#define TCP_SERVER_RX_BUFFER_SIZE   128
#define TCP_SERVER_RETRY_DELAY_MS   2000
#define CAPTURE_START_DELAY_MS      5000


static void do_retransmit(const int sock)
{
    int len = 0;
    char rx_buffer[TCP_SERVER_RX_BUFFER_SIZE];

    do {
        len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len < 0) {
        } else if (len == 0) {
        } else {
            rx_buffer[len] = '\0';
            int to_write = len;
            while (to_write > 0) {
                int written = send(sock, rx_buffer + (len - to_write), to_write, 0);
                if (written < 0) {
                    return;
                }
                to_write -= written;
            }
        }
    } while (len > 0);
}

static void tcp_server_task(void *pvParameters)
{
    (void)pvParameters;

    while (1) {
        struct sockaddr_in listen_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(TCP_SERVER_PORT),
            .sin_addr.s_addr = htonl(INADDR_ANY),
        };

        int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (listen_sock < 0) {
            vTaskDelay(pdMS_TO_TICKS(TCP_SERVER_RETRY_DELAY_MS));
            continue;
        }

        int keep_alive = 1;
        int keep_idle = 5;
        int keep_interval = 5;
        int keep_count = 3;
        setsockopt(listen_sock, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
        setsockopt(listen_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keep_idle, sizeof(int));
        setsockopt(listen_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keep_interval, sizeof(int));
        setsockopt(listen_sock, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(int));

        int err = bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
        if (err != 0) {
            close(listen_sock);
            vTaskDelay(pdMS_TO_TICKS(TCP_SERVER_RETRY_DELAY_MS));
            continue;
        }

        err = listen(listen_sock, 1);
        if (err != 0) {
            close(listen_sock);
            vTaskDelay(pdMS_TO_TICKS(TCP_SERVER_RETRY_DELAY_MS));
            continue;
        }

        struct sockaddr_storage source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        if (sock < 0) {
            close(listen_sock);
            vTaskDelay(pdMS_TO_TICKS(TCP_SERVER_RETRY_DELAY_MS));
            continue;
        }

        do_retransmit(sock);

        shutdown(sock, 0);
        close(sock);
        close(listen_sock);
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ret = wifi_manager_init(WIFI_SSID, WIFI_PASSWORD, true);
    if (ret != ESP_OK) {
        return;
    }

    if (!wifi_manager_wait_connected(30000)) {
        return;
    }

    if (CAPTURE_START_DELAY_MS > 0) {
        packet_capture_set_enabled(false);
        vTaskDelay(pdMS_TO_TICKS(CAPTURE_START_DELAY_MS));
        packet_capture_set_enabled(true);
    }

    // Start TCP server after Wi-Fi is connected
    xTaskCreate(tcp_server_task,
                "tcp_server",
                TCP_SERVER_TASK_STACK_WORDS,
                NULL,
                TCP_SERVER_TASK_PRIORITY,
                NULL);

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
