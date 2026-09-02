#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* On-disk format = ProjectZero's oui_wifi.bin: a header-less array of 64-byte
 * records, each { uint8_t oui[3]; uint8_t name_len; char name[60] }, sorted
 * ascending by oui for binary search. (This is the file ProjectZero ships in
 * binaries-esp32c5/oui_wifi.bin.) */
#define OUI_DEFAULT_PATH  "/sdcard/lab/oui_wifi.bin"

/* Load OUI database from bin_path into PSRAM.
 * Returns ESP_OK on success, ESP_ERR_NOT_FOUND if file absent. */
esp_err_t   oui_lookup_init(const char *bin_path);

/* Look up a 3-byte OUI prefix in standard order {AA, BB, CC}.
 * For NimBLE addresses use {addr[5], addr[4], addr[3]}.
 * Returns vendor name string (valid until oui_lookup_deinit), or NULL. */
const char *oui_lookup(const uint8_t oui3[3]);

bool        oui_lookup_is_loaded(void);
uint32_t    oui_lookup_count(void);
void        oui_lookup_deinit(void);
