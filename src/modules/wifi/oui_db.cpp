#include "oui_db.h"

#include <string.h>

// Seed table. Prefixes are IEEE OUI assignments for the relevant vendors; this is
// a curated, best-effort seed (extend from SD later - see oui_db.h). Generic Wi-Fi
// module makers (Espressif / Realtek) are included as OUI_GENERIC so detectors can
// mark them low-confidence rather than claim a positive camera identification.
static const OuiEntry OUI_TABLE[] = {
    // ── IP / wireless camera vendors ────────────────────────────────────────
    // Hikvision / Ezviz (Hangzhou Hikvision Digital Technology)
    {{0x44, 0x19, 0xB6}, "Hikvision", OUI_CAM},
    {{0x28, 0x57, 0xBE}, "Hikvision", OUI_CAM},
    {{0xC0, 0x56, 0xE3}, "Hikvision", OUI_CAM},
    {{0x4C, 0xBD, 0x8F}, "Hikvision", OUI_CAM},
    {{0xBC, 0xAD, 0x28}, "Hikvision", OUI_CAM},
    {{0x54, 0xC4, 0x15}, "Hikvision", OUI_CAM},
    {{0x58, 0x03, 0xFB}, "Hikvision", OUI_CAM},
    // Dahua Technology
    {{0x3C, 0xEF, 0x8C}, "Dahua", OUI_CAM},
    {{0x90, 0x02, 0xA9}, "Dahua", OUI_CAM},
    {{0x08, 0xED, 0xED}, "Dahua", OUI_CAM},
    {{0x14, 0xA7, 0x8B}, "Dahua", OUI_CAM},
    {{0xE0, 0x50, 0x8B}, "Dahua", OUI_CAM},
    {{0x38, 0xAF, 0x29}, "Dahua", OUI_CAM},
    // Amcrest
    {{0x9C, 0x8E, 0xCD}, "Amcrest", OUI_CAM},
    // Wyze Labs
    {{0x2C, 0xAA, 0x8E}, "Wyze", OUI_CAM},
    {{0x7C, 0x78, 0xB2}, "Wyze", OUI_CAM},
    {{0xD0, 0x3F, 0x27}, "Wyze", OUI_CAM},
    // Reolink / Baichuan
    {{0xEC, 0x71, 0xDB}, "Reolink", OUI_CAM},

    // ── Drone / UAV makers ──────────────────────────────────────────────────
    // SZ DJI Technology
    {{0x60, 0x60, 0x1F}, "DJI", OUI_DRONE},
    {{0x34, 0xD2, 0x62}, "DJI", OUI_DRONE},
    {{0x48, 0x1C, 0xB9}, "DJI", OUI_DRONE},
    // Parrot
    {{0x00, 0x12, 0x1C}, "Parrot", OUI_DRONE},
    {{0x90, 0x03, 0xB7}, "Parrot", OUI_DRONE},
    {{0xA0, 0x14, 0x3D}, "Parrot", OUI_DRONE},
    {{0x00, 0x26, 0x7E}, "Parrot", OUI_DRONE},

    // ── General IoT vendors common in surveillance gadgets ──────────────────
    // Xiaomi
    {{0x64, 0x09, 0x80}, "Xiaomi", OUI_IOT},
    {{0x78, 0x11, 0xDC}, "Xiaomi", OUI_IOT},
    {{0x50, 0xEC, 0x50}, "Xiaomi", OUI_IOT},
    {{0xF0, 0xB4, 0x29}, "Xiaomi", OUI_IOT},
    {{0x28, 0x6C, 0x07}, "Xiaomi", OUI_IOT},

    // ── Generic Wi-Fi module vendors (LOW CONFIDENCE) ───────────────────────
    // Espressif (ESP8266 / ESP32) - used by countless cheap IoT cams & gadgets
    {{0x24, 0x0A, 0xC4}, "Espressif", OUI_GENERIC},
    {{0x24, 0x6F, 0x28}, "Espressif", OUI_GENERIC},
    {{0x30, 0xAE, 0xA4}, "Espressif", OUI_GENERIC},
    {{0x3C, 0x71, 0xBF}, "Espressif", OUI_GENERIC},
    {{0x7C, 0x9E, 0xBD}, "Espressif", OUI_GENERIC},
    {{0x84, 0xCC, 0xA8}, "Espressif", OUI_GENERIC},
    {{0x8C, 0xAA, 0xB5}, "Espressif", OUI_GENERIC},
    {{0xA4, 0xCF, 0x12}, "Espressif", OUI_GENERIC},
    {{0xB4, 0xE6, 0x2D}, "Espressif", OUI_GENERIC},
    {{0xCC, 0x50, 0xE3}, "Espressif", OUI_GENERIC},
    {{0xDC, 0x4F, 0x22}, "Espressif", OUI_GENERIC},
    {{0xEC, 0xFA, 0xBC}, "Espressif", OUI_GENERIC},
    {{0x18, 0xFE, 0x34}, "Espressif", OUI_GENERIC},
    {{0x5C, 0xCF, 0x7F}, "Espressif", OUI_GENERIC},
    {{0xAC, 0xD0, 0x74}, "Espressif", OUI_GENERIC},
    // Realtek Semiconductor
    {{0x00, 0xE0, 0x4C}, "Realtek", OUI_GENERIC},
};

static const size_t OUI_TABLE_N = sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]);

const char *ouiClassName(uint8_t klass) {
    switch (klass) {
    case OUI_CAM: return "CAM";
    case OUI_DRONE: return "DRONE";
    case OUI_IOT: return "IOT";
    case OUI_GENERIC: return "GENERIC";
    default: return "?";
    }
}

const OuiEntry *lookupOui(const uint8_t *mac) {
    if (!mac) return nullptr;
    for (size_t i = 0; i < OUI_TABLE_N; i++) {
        if (memcmp(OUI_TABLE[i].oui, mac, 3) == 0) return &OUI_TABLE[i];
    }
    return nullptr;
}

size_t ouiTableSize() { return OUI_TABLE_N; }
