#ifndef __LORA_PROFILES_H__
#define __LORA_PROFILES_H__
#if !defined(LITE_VERSION)

#include "lora_classify.h"
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// LoRa receive profiles: where each mesh network lives. The recon cycles these,
// retuning the radio and dwelling on each. Phase 2a seeds the Meshtastic +
// MeshCore presets for EU868 and US915 (the T-Deck's native bands); 433 MHz ham
// presets (APRS/MeshCom) are omitted - this EU868 unit's antenna/matching make
// 433 reception unreliable. Frequencies/PHY from skizzophrenic/SquachWatch-CYD
// lora_profiles.cpp (GPL-3.0; factual radio parameters).
// ---------------------------------------------------------------------------

namespace loramp {

enum Region : uint8_t { REGION_EU = 0, REGION_US = 1 };

enum ProfFlags : uint8_t {
    PFL_CRC = 0x01,    // CRC on
    PFL_INVERT = 0x02, // inverted IQ
};

struct Profile {
    const char *name;
    uint32_t freqHz;
    uint16_t bwKhz10; // 100 Hz units: 2500 = 250 kHz, 625 = 62.5 kHz
    uint8_t sf;
    uint8_t cr;    // 5..8
    uint8_t sync;  // 0x2B Meshtastic, 0x12 MeshCore
    uint16_t preamble;
    uint8_t flags; // ProfFlags
    Proto hint;    // what usually lives here
};

const char *regionName(Region r);
// The active region's profile table and its length.
const Profile *profiles(Region r, size_t &countOut);

} // namespace loramp

#endif
#endif // __LORA_PROFILES_H__
