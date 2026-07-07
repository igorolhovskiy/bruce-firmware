#ifndef __OUI_DB_H__
#define __OUI_DB_H__

#include <stdint.h>
#include <stddef.h>

// ─────────────────────────────────────────────────────────────────────────────
// Compact, counter-surveillance-focused OUI (MAC vendor-prefix) database. This is
// deliberately NOT the full ~30k-entry IEEE registry: it seeds only vendors that
// matter to the Detector suite - IP/wireless camera makers, drone makers, and the
// generic ESP/Realtek Wi-Fi module vendors that many cheap spy gadgets reuse
// (flagged GENERIC -> low confidence). Matching is a linear scan on the 3-byte
// prefix, trivially fast at Wi-Fi frame rates. Shared by the WiFi Camera,
// BLE Spy Tag, and Follower detectors. Designed so the table can later be
// extended from an SD file without touching callers.
// ─────────────────────────────────────────────────────────────────────────────

enum OuiClass : uint8_t {
    OUI_NONE = 0,
    OUI_CAM,     // known IP / wireless camera vendor -> high confidence
    OUI_DRONE,   // known drone / UAV maker
    OUI_IOT,     // general IoT vendor often used in surveillance gadgets
    OUI_GENERIC, // generic Wi-Fi module vendor (ESP/Realtek) -> low confidence
};

struct OuiEntry {
    uint8_t oui[3];
    const char *vendor;
    uint8_t klass; // OuiClass
};

// Human-readable name for a class code.
const char *ouiClassName(uint8_t klass);

// Look up the first 3 bytes of `mac` (a 6-byte address) in the seed table.
// Returns the matching entry, or nullptr if the prefix is unknown.
const OuiEntry *lookupOui(const uint8_t *mac);

// Number of entries in the seed table (for tests / diagnostics).
size_t ouiTableSize();

#endif // __OUI_DB_H__
