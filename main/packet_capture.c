/**
 * TLV framing (v2):
 *   SYNC(0xAA55)[2] + TOTAL_LEN(full frame, BE)[2] + VER[1] + TLVs...
 *
 * TLVs:
 *   0x01: TIMESTAMP (8 bytes, uint64, microseconds, BE)
 *   0x02: DIRECTION (1 byte, 0=RX, 1=TX)
 *   0x03: SEQ (4 bytes, uint32, BE)
 *   0x10: PACKET_DATA (N bytes, raw Ethernet frame)
 *   0x11: CRC32 (4 bytes, uint32, BE) - MUST be the last TLV
 *
 * Cơ chế:
 *   Copy pbuf bytes từ netif hooks vào ring buffer
 */

#include "packet_capture.h"

#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_rom_crc.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// =========================
// TLV types
// =========================
#define TLV_TYPE_TIMESTAMP    0x01
#define TLV_TYPE_DIRECTION    0x02
#define TLV_TYPE_SEQ          0x03
#define TLV_TYPE_PACKET_DATA  0x10
#define TLV_TYPE_CRC32        0x11

// =========================
// Capture pool configuration
// =========================

#ifndef PACKET_CAPTURE_MAX_PACKET_SIZE
#define PACKET_CAPTURE_MAX_PACKET_SIZE 2048U
#endif

// TLV frame size = packet_len + overhead.
// Overhead = header(5) + ts_tlv(11) + dir_tlv(4) + seq_tlv(7) + pkt_hdr(3) + crc_tlv(7)
#define TLV_FRAME_OVERHEAD_BYTES 37U
#define TLV_FRAME_MAX_SIZE (TLV_FRAME_OVERHEAD_BYTES + PACKET_CAPTURE_MAX_PACKET_SIZE)

#ifndef PACKET_CAPTURE_WAIT_MS_WHEN_FULL
#define PACKET_CAPTURE_WAIT_MS_WHEN_FULL 10U
#endif

typedef struct {
    uint16_t len;
    uint8_t is_tx;
    uint8_t _rsv;
    uint32_t seq;
    int64_t timestamp_us;
    uint8_t data[PACKET_CAPTURE_MAX_PACKET_SIZE];
} capture_slot_t;

static uint32_t s_frame_seq = 0;

static struct {
    struct netif *lwip_netif;
    netif_input_fn original_input_fn;
    netif_linkoutput_fn original_linkoutput_fn;

    packet_stats_t stats;
    bool installed;
    bool capture_enabled;

    // Pool / ring
    capture_slot_t *slots;
    uint16_t slot_count;
    QueueHandle_t free_q;   // uint16_t slot index
    QueueHandle_t filled_q; // uint16_t slot index
    bool drop_on_full;

    TaskHandle_t processing_task;
} g_capture_ctx = {0};

static void packet_process_task(void *pvParameters);
static err_t custom_packet_input(struct pbuf *p, struct netif *inp);
static err_t custom_packet_output(struct netif *netif, struct pbuf *p);
static void packet_capture_cleanup_resources(void);
static void packet_capture_install_hooks_on_tcpip(void *arg);

static void update_protocol_stats_from_eth(const uint8_t *data, size_t len);
static void send_raw_packet_to_serial(uint8_t *frame_buf,
                                      size_t frame_buf_cap,
                                      const uint8_t *data,
                                      size_t len,
                                      bool is_tx,
                                      int64_t timestamp_us,
                                      uint32_t seq);

static inline uint32_t next_seq_relaxed(void)
{
    // Thread-safe
    return __atomic_add_fetch(&s_frame_seq, 1, __ATOMIC_RELAXED);
}

static inline TickType_t slot_wait_ticks(void)
{
    return g_capture_ctx.drop_on_full ? 0 : pdMS_TO_TICKS(PACKET_CAPTURE_WAIT_MS_WHEN_FULL);
}

static void try_enqueue_snapshot(struct pbuf *p, bool is_tx)
{
    if (!p || !g_capture_ctx.slots || !g_capture_ctx.free_q || !g_capture_ctx.filled_q) {
        return;
    }
    if (!__atomic_load_n(&g_capture_ctx.capture_enabled, __ATOMIC_RELAXED)) {
        return;
    }

    const uint32_t seq = next_seq_relaxed();

    uint16_t idx = 0;
    if (xQueueReceive(g_capture_ctx.free_q, &idx, slot_wait_ticks()) != pdTRUE) {
        g_capture_ctx.stats.queue_dropped++;
        return;
    }

    capture_slot_t *slot = &g_capture_ctx.slots[idx];

    const size_t len = (size_t)p->tot_len;
    if (len == 0 || len > (size_t)PACKET_CAPTURE_MAX_PACKET_SIZE) {
        g_capture_ctx.stats.queue_dropped++;
        (void)xQueueSend(g_capture_ctx.free_q, &idx, 0);
        return;
    }

    const uint16_t copied = (uint16_t)pbuf_copy_partial(p, slot->data, (u16_t)len, 0);
    if (copied != (uint16_t)len) {
        g_capture_ctx.stats.queue_dropped++;
        (void)xQueueSend(g_capture_ctx.free_q, &idx, 0);
        return;
    }

    slot->len = (uint16_t)len;
    slot->is_tx = is_tx ? 1 : 0;
    slot->seq = seq;
    slot->timestamp_us = esp_timer_get_time();

    if (xQueueSend(g_capture_ctx.filled_q, &idx, 0) != pdTRUE) {
        g_capture_ctx.stats.queue_dropped++;
        (void)xQueueSend(g_capture_ctx.free_q, &idx, 0);
        return;
    }
}

static err_t custom_packet_input(struct pbuf *p, struct netif *inp)
{
    if (!p || !inp) {
        if (p) {
            pbuf_free(p);
        }
        return ERR_ARG;
    }

    g_capture_ctx.stats.total_packets++;
    g_capture_ctx.stats.total_bytes += p->tot_len;

    try_enqueue_snapshot(p, false);

    if (g_capture_ctx.original_input_fn) {
        return g_capture_ctx.original_input_fn(p, inp);
    }

    pbuf_free(p);
    return ERR_IF;
}

static err_t custom_packet_output(struct netif *netif, struct pbuf *p)
{
    if (!netif || !p) {
        if (p) {
            pbuf_free(p);
        }
        return ERR_ARG;
    }

    g_capture_ctx.stats.total_packets++;
    g_capture_ctx.stats.total_bytes += p->tot_len;

    try_enqueue_snapshot(p, true);

    if (g_capture_ctx.original_linkoutput_fn) {
        return g_capture_ctx.original_linkoutput_fn(netif, p);
    }

    return ERR_IF;
}

static void packet_capture_cleanup_resources(void)
{
    if (g_capture_ctx.processing_task) {
        vTaskDelete(g_capture_ctx.processing_task);
        g_capture_ctx.processing_task = NULL;
    }
    if (g_capture_ctx.free_q) {
        vQueueDelete(g_capture_ctx.free_q);
        g_capture_ctx.free_q = NULL;
    }
    if (g_capture_ctx.filled_q) {
        vQueueDelete(g_capture_ctx.filled_q);
        g_capture_ctx.filled_q = NULL;
    }
    if (g_capture_ctx.slots) {
        free(g_capture_ctx.slots);
        g_capture_ctx.slots = NULL;
    }
    g_capture_ctx.slot_count = 0;
    g_capture_ctx.drop_on_full = false;
}

typedef struct {
    esp_netif_t *esp_netif;
    SemaphoreHandle_t done;
    esp_err_t result;
} packet_capture_hook_ctx_t;

static void packet_capture_install_hooks_on_tcpip(void *arg)
{
    packet_capture_hook_ctx_t *ctx = (packet_capture_hook_ctx_t *)arg;
    struct netif *lwip_netif = esp_netif_get_netif_impl(ctx->esp_netif);
    if (!lwip_netif || !lwip_netif->input || !lwip_netif->linkoutput) {
        ctx->result = ESP_FAIL;
        xSemaphoreGive(ctx->done);
        return;
    }

    g_capture_ctx.lwip_netif = lwip_netif;
    g_capture_ctx.original_input_fn = lwip_netif->input;
    g_capture_ctx.original_linkoutput_fn = lwip_netif->linkoutput;

    lwip_netif->input = custom_packet_input;
    lwip_netif->linkoutput = custom_packet_output;

    ctx->result = ESP_OK;
    xSemaphoreGive(ctx->done);
}

static void packet_process_task(void *pvParameters)
{
    (void)pvParameters;

    // Reuse a single frame buffer to avoid per-packet malloc/free.
    uint8_t *frame_buf = (uint8_t *)malloc(TLV_FRAME_MAX_SIZE);
    const size_t frame_buf_cap = frame_buf ? (size_t)TLV_FRAME_MAX_SIZE : 0;

    while (1) {
        uint16_t idx = 0;
        if (xQueueReceive(g_capture_ctx.filled_q, &idx, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (!g_capture_ctx.slots || idx >= g_capture_ctx.slot_count) {
            if (g_capture_ctx.free_q) {
                (void)xQueueSend(g_capture_ctx.free_q, &idx, 0);
            }
            continue;
        }

        capture_slot_t *slot = &g_capture_ctx.slots[idx];

        update_protocol_stats_from_eth(slot->data, (size_t)slot->len);

        send_raw_packet_to_serial(frame_buf, frame_buf_cap,
                                  slot->data, (size_t)slot->len,
                                  slot->is_tx != 0,
                                  slot->timestamp_us,
                                  slot->seq);

        // Return slot to free pool.
        (void)xQueueSend(g_capture_ctx.free_q, &idx, 0);
    }

    // free(frame_buf);
    // vTaskDelete(NULL);
}

static void update_protocol_stats_from_eth(const uint8_t *data, size_t len)
{
    if (!data || len < 14) {
        g_capture_ctx.stats.other_packets++;
        return;
    }

    const uint16_t ethertype = (uint16_t)((data[12] << 8) | data[13]);

    switch (ethertype) {
    case 0x0806: // ARP
        g_capture_ctx.stats.arp_packets++;
        return;

    case 0x86DD: { // IPv6
        g_capture_ctx.stats.ipv6_packets++;
        if (len < 14 + 40) {
            g_capture_ctx.stats.other_packets++;
            return;
        }
        const uint8_t next_header = data[14 + 6];
        if (next_header == 58) {
            g_capture_ctx.stats.icmp_packets++;
        } else if (next_header == 6) {
            g_capture_ctx.stats.tcp_packets++;
        } else if (next_header == 17) {
            g_capture_ctx.stats.udp_packets++;
        } else {
            g_capture_ctx.stats.other_packets++;
        }
        return;
    }

    case 0x0800: { // IPv4
        if (len < 14 + 20) {
            g_capture_ctx.stats.other_packets++;
            return;
        }

        const uint8_t vihl = data[14];
        const uint8_t version = (uint8_t)(vihl >> 4);
        const uint8_t ihl = (uint8_t)(vihl & 0x0F);
        if (version != 4 || ihl < 5) {
            g_capture_ctx.stats.other_packets++;
            return;
        }

        const size_t ip_hdr_len = (size_t)ihl * 4;
        if (len < 14 + ip_hdr_len) {
            g_capture_ctx.stats.other_packets++;
            return;
        }

        const uint8_t proto = data[14 + 9];
        if (proto == 1) {
            g_capture_ctx.stats.icmp_packets++;
        } else if (proto == 6) {
            g_capture_ctx.stats.tcp_packets++;
        } else if (proto == 17) {
            g_capture_ctx.stats.udp_packets++;
        } else {
            g_capture_ctx.stats.other_packets++;
        }
        return;
    }

    default:
        g_capture_ctx.stats.other_packets++;
        return;
    }
}

static void send_raw_packet_to_serial(uint8_t *frame_buf,
                                      size_t frame_buf_cap,
                                      const uint8_t *data,
                                      size_t len,
                                      bool is_tx,
                                      int64_t timestamp_us,
                                      uint32_t seq)
{
    if (!data || len == 0) {
        return;
    }

    // Frame format:
    //   SYNC(0xAA55)[2] + TOTAL_LEN(full frame, BE)[2] + VER[1] + TLVs...

    const uint8_t ver = 0x01;

    const size_t timestamp_tlv_size = 1 + 2 + 8;
    const size_t direction_tlv_size = 1 + 2 + 1;
    const size_t seq_tlv_size = 1 + 2 + 4;
    const size_t packet_tlv_size = 1 + 2 + len;
    const size_t crc32_tlv_size = 1 + 2 + 4;

    const size_t total_frame_size = 5 + timestamp_tlv_size + direction_tlv_size +
                                    seq_tlv_size + packet_tlv_size + crc32_tlv_size;

    if (total_frame_size > UINT16_MAX) {
        return;
    }

    uint8_t *frame = NULL;
    bool use_temp_malloc = false;

    if (frame_buf && frame_buf_cap >= total_frame_size) {
        frame = frame_buf;
    } else {
        frame = (uint8_t *)malloc(total_frame_size);
        if (!frame) {
            return;
        }
        use_temp_malloc = true;
    }

    uint8_t *ptr = frame;

    // Header
    *ptr++ = 0xAA;
    *ptr++ = 0x55;
    *ptr++ = (uint8_t)((total_frame_size >> 8) & 0xFF);
    *ptr++ = (uint8_t)(total_frame_size & 0xFF);
    *ptr++ = ver;

    // TLV Timestamp
    *ptr++ = TLV_TYPE_TIMESTAMP;
    *ptr++ = 0x00;
    *ptr++ = 0x08;
    const uint64_t ts_val = (timestamp_us < 0) ? 0ULL : (uint64_t)timestamp_us;
    for (int i = 7; i >= 0; --i) {
        *ptr++ = (uint8_t)((ts_val >> (i * 8)) & 0xFF);
    }

    // TLV Direction
    *ptr++ = TLV_TYPE_DIRECTION;
    *ptr++ = 0x00;
    *ptr++ = 0x01;
    *ptr++ = is_tx ? 0x01 : 0x00;

    // TLV Sequence number
    *ptr++ = TLV_TYPE_SEQ;
    *ptr++ = 0x00;
    *ptr++ = 0x04;
    *ptr++ = (uint8_t)((seq >> 24) & 0xFF);
    *ptr++ = (uint8_t)((seq >> 16) & 0xFF);
    *ptr++ = (uint8_t)((seq >> 8) & 0xFF);
    *ptr++ = (uint8_t)(seq & 0xFF);

    // TLV Packet Data
    *ptr++ = TLV_TYPE_PACKET_DATA;
    *ptr++ = (uint8_t)((len >> 8) & 0xFF);
    *ptr++ = (uint8_t)(len & 0xFF);
    memcpy(ptr, data, len);
    ptr += len;

    // CRC32: VER + TLVs (excluding CRC32 TLV itself)
    const size_t crc_region_offset = 4; // start at VER (frame[4])
    const size_t crc_region_len = (size_t)(ptr - (frame + crc_region_offset));
    const uint32_t crc = esp_rom_crc32_le(0, frame + crc_region_offset, crc_region_len);

    // TLV CRC32 (last TLV)
    *ptr++ = TLV_TYPE_CRC32;
    *ptr++ = 0x00;
    *ptr++ = 0x04;
    *ptr++ = (uint8_t)((crc >> 24) & 0xFF);
    *ptr++ = (uint8_t)((crc >> 16) & 0xFF);
    *ptr++ = (uint8_t)((crc >> 8) & 0xFF);
    *ptr++ = (uint8_t)(crc & 0xFF);

    // Safety: ptr = computed size. 
    if ((size_t)(ptr - frame) == total_frame_size) {
        fwrite(frame, total_frame_size, 1, stdout);
        fflush(stdout);
    }

    if (use_temp_malloc) {
        free(frame);
    }
}

esp_err_t packet_capture_install_hook_with_config(esp_netif_t *esp_netif,
                                                 const packet_capture_config_t *config)
{
    if (!esp_netif || !config) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_capture_ctx.installed) {
        return ESP_OK;
    }

    (void)setvbuf(stdout, NULL, _IONBF, 0);

    memset(&g_capture_ctx.stats, 0, sizeof(packet_stats_t));
    __atomic_store_n(&g_capture_ctx.capture_enabled, true, __ATOMIC_RELAXED);

    const uint16_t slot_count = config->queue_size ? config->queue_size
                                                   : PACKET_CAPTURE_DEFAULT_QUEUE_SIZE;
    g_capture_ctx.slot_count = slot_count;
    g_capture_ctx.drop_on_full = config->drop_when_full;

    g_capture_ctx.slots = (capture_slot_t *)calloc((size_t)slot_count, sizeof(capture_slot_t));
    if (!g_capture_ctx.slots) {
        return ESP_ERR_NO_MEM;
    }

    // 2 ring buffer:
    // free_q
    // filled_q
    g_capture_ctx.free_q = xQueueCreate(slot_count, sizeof(uint16_t));
    g_capture_ctx.filled_q = xQueueCreate(slot_count, sizeof(uint16_t));
    if (!g_capture_ctx.free_q || !g_capture_ctx.filled_q) {
        packet_capture_cleanup_resources();
        return ESP_ERR_NO_MEM;
    }

    // Seed free_q with all indices.
    for (uint16_t i = 0; i < slot_count; i++) {
        (void)xQueueSend(g_capture_ctx.free_q, &i, 0);
    }

    if (xTaskCreate(packet_process_task,
                    "packet_process_task",
                    4096,
                    NULL,
                    5,
                    &g_capture_ctx.processing_task) != pdPASS) {
        packet_capture_cleanup_resources();
        return ESP_FAIL;
    }

    packet_capture_hook_ctx_t hook_ctx = {
        .esp_netif = esp_netif,
        .done = xSemaphoreCreateBinary(),
        .result = ESP_FAIL,
    };
    if (!hook_ctx.done) {
        packet_capture_cleanup_resources();
        return ESP_ERR_NO_MEM;
    }

    err_t cb_ret = tcpip_callback(packet_capture_install_hooks_on_tcpip, &hook_ctx);
    if (cb_ret != ERR_OK) {
        vSemaphoreDelete(hook_ctx.done);
        packet_capture_cleanup_resources();
        return ESP_FAIL;
    }

    if (xSemaphoreTake(hook_ctx.done, pdMS_TO_TICKS(2000)) != pdTRUE) {
        vSemaphoreDelete(hook_ctx.done);
        packet_capture_cleanup_resources();
        return ESP_ERR_TIMEOUT;
    }

    vSemaphoreDelete(hook_ctx.done);
    if (hook_ctx.result != ESP_OK) {
        packet_capture_cleanup_resources();
        return hook_ctx.result;
    }

    g_capture_ctx.installed = true;
    return ESP_OK;
}

esp_err_t packet_capture_install_hook(esp_netif_t *esp_netif)
{
    packet_capture_config_t cfg = {
        .queue_size = PACKET_CAPTURE_DEFAULT_QUEUE_SIZE,
        .drop_when_full = PACKET_CAPTURE_DEFAULT_DROP_WHEN_FULL,
    };

    return packet_capture_install_hook_with_config(esp_netif, &cfg);
}

esp_err_t packet_capture_get_stats(packet_stats_t *stats)
{
    if (!stats) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(stats, &g_capture_ctx.stats, sizeof(packet_stats_t));
    return ESP_OK;
}

void packet_capture_reset_stats(void)
{
    memset(&g_capture_ctx.stats, 0, sizeof(packet_stats_t));
}

void packet_capture_set_enabled(bool enabled)
{
    __atomic_store_n(&g_capture_ctx.capture_enabled, enabled, __ATOMIC_RELAXED);
}

bool packet_capture_is_enabled(void)
{
    return __atomic_load_n(&g_capture_ctx.capture_enabled, __ATOMIC_RELAXED);
}
