// wifi_common.c - Common helper functions
#include "wifi_common.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

// Global variables (defined once, extern in header)
led_strip_handle_t g_led_strip = NULL;
volatile app_state_t g_app_state = APP_STATE_IDLE;
volatile bool g_operation_stop_requested = false;

void led_set_state(uint8_t r, uint8_t g, uint8_t b) {
    if (!g_led_strip) return;
    led_strip_set_pixel(g_led_strip, 0, r, g, b);
    led_strip_refresh(g_led_strip);
}

// Matches cyberbrick boot sequence: R→G→B→white (120ms each), 3× white blink (80ms on/off)
#define BOOT_BRIGHT 40
void led_boot_sequence(void) {
    if (!g_led_strip) return;
    // Wipe R → G → B → white
    uint8_t colors[4][3] = {
        {BOOT_BRIGHT, 0,           0          },
        {0,           BOOT_BRIGHT, 0          },
        {0,           0,           BOOT_BRIGHT},
        {BOOT_BRIGHT, BOOT_BRIGHT, BOOT_BRIGHT},
    };
    for (int i = 0; i < 4; i++) {
        led_set_state(colors[i][0], colors[i][1], colors[i][2]);
        vTaskDelay(pdMS_TO_TICKS(120));
    }
    // Three quick white blinks
    for (int i = 0; i < 3; i++) {
        led_set_state(BOOT_BRIGHT, BOOT_BRIGHT, BOOT_BRIGHT);
        vTaskDelay(pdMS_TO_TICKS(80));
        led_set_state(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(80));
    }
}

const char* authmode_to_string(wifi_auth_mode_t mode) {
    switch (mode) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK: return "WAPI_PSK";
        default: return "Unknown";
    }
}

void escape_csv_field(const char* input, char* output, size_t output_size) {
    size_t i = 0, j = 0;
    bool needs_quotes = false;
    
    if (!input || !output || output_size < 3) return;
    
    for (i = 0; input[i] != '\0'; i++) {
        if (input[i] == ',' || input[i] == '"' || input[i] == '\n') {
            needs_quotes = true;
            break;
        }
    }
    
    if (needs_quotes) {
        output[j++] = '"';
        for (i = 0; input[i] != '\0' && j < output_size - 3; i++) {
            if (input[i] == '"') {
                output[j++] = '"';
                output[j++] = '"';
            } else {
                output[j++] = input[i];
            }
        }
        output[j++] = '"';
        output[j] = '\0';
    } else {
        strncpy(output, input, output_size - 1);
        output[output_size - 1] = '\0';
    }
}

bool is_multicast_mac(const uint8_t *mac) {
    return (mac[0] & 0x01) != 0;
}

bool is_broadcast_bssid(const uint8_t *bssid) {
    return (bssid[0] == 0xFF && bssid[1] == 0xFF && bssid[2] == 0xFF &&
            bssid[3] == 0xFF && bssid[4] == 0xFF && bssid[5] == 0xFF);
}

bool is_own_device_mac(const uint8_t *mac) {
    uint8_t own_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, own_mac);
    return memcmp(mac, own_mac, 6) == 0;
}
