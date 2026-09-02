#include "oui_lookup.h"
#include <string.h>
#include <stdio.h>
#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "oui_lookup";

#define OUI_ENTRY_SIZE      32  /* in-RAM: oui[3] + name[29] (name truncated for display) */
#define OUI_SRC_RECORD_SIZE 64  /* on-disk (oui_wifi.bin): oui[3] + name_len[1] + name[60] */

typedef struct __attribute__((packed)) {
    uint8_t oui[3];
    char    name[29];
} oui_entry_t;

_Static_assert(sizeof(oui_entry_t) == OUI_ENTRY_SIZE, "oui_entry_t size mismatch");

static oui_entry_t *s_table = NULL;
static uint32_t     s_count = 0;

esp_err_t oui_lookup_init(const char *bin_path)
{
    oui_lookup_deinit();

    FILE *f = fopen(bin_path, "rb");
    if (!f) {
        ESP_LOGW(TAG, "Not found: %s", bin_path);
        return ESP_ERR_NOT_FOUND;
    }

    // Size the file: header-less array of 64-byte records.
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return ESP_FAIL; }
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < OUI_SRC_RECORD_SIZE) {
        ESP_LOGE(TAG, "Too small / bad OUI file: %s (%ld bytes)", bin_path, fsize);
        fclose(f);
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t count = (uint32_t)(fsize / OUI_SRC_RECORD_SIZE);

    // Slurp the whole file into a temporary PSRAM buffer, then repack the
    // length-prefixed 64-byte records into our compact 32-byte in-RAM entries.
    uint8_t *raw = (uint8_t *)heap_caps_malloc((size_t)fsize, MALLOC_CAP_SPIRAM);
    s_table = (oui_entry_t *)heap_caps_malloc((size_t)count * OUI_ENTRY_SIZE, MALLOC_CAP_SPIRAM);
    if (!raw || !s_table) {
        ESP_LOGE(TAG, "PSRAM alloc failed (raw=%p table=%p)", (void *)raw, (void *)s_table);
        if (raw) free(raw);
        if (s_table) { free(s_table); s_table = NULL; }
        fclose(f);
        return ESP_ERR_NO_MEM;
    }
    size_t got = fread(raw, 1, (size_t)fsize, f);
    fclose(f);
    if (got != (size_t)fsize) {
        ESP_LOGE(TAG, "Short read from %s (%u/%ld)", bin_path, (unsigned)got, fsize);
        free(raw);
        free(s_table);
        s_table = NULL;
        return ESP_FAIL;
    }

    const size_t name_cap = sizeof(s_table[0].name) - 1;   // 28 usable chars
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *rec = raw + (size_t)i * OUI_SRC_RECORD_SIZE;
        s_table[i].oui[0] = rec[0];
        s_table[i].oui[1] = rec[1];
        s_table[i].oui[2] = rec[2];
        uint8_t nlen = rec[3];
        if (nlen > name_cap) nlen = (uint8_t)name_cap;
        memcpy(s_table[i].name, &rec[4], nlen);
        s_table[i].name[nlen] = '\0';
    }
    free(raw);

    s_count = count;
    ESP_LOGI(TAG, "Loaded %u OUI entries from %s", (unsigned)count, bin_path);
    return ESP_OK;
}

const char *oui_lookup(const uint8_t oui3[3])
{
    if (!s_table || s_count == 0) return NULL;
    int lo = 0, hi = (int)s_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int cmp = memcmp(s_table[mid].oui, oui3, 3);
        if      (cmp == 0) return s_table[mid].name;
        else if (cmp < 0)  lo = mid + 1;
        else               hi = mid - 1;
    }
    return NULL;
}

bool     oui_lookup_is_loaded(void) { return s_table != NULL; }
uint32_t oui_lookup_count(void)     { return s_count; }

void oui_lookup_deinit(void)
{
    if (s_table) { free(s_table); s_table = NULL; }
    s_count = 0;
}
