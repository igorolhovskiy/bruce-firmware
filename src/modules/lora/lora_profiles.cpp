#include "lora_profiles.h"
#if !defined(LITE_VERSION)

namespace loramp {

// EU868 mesh presets (Meshtastic sync 0x2B, MeshCore sync 0x12). The common
// German-default LongFast first so a short survey still catches the busy one.
static const Profile PROFILES_EU[] = {
    {"MT LongFast", 869525000, 2500, 11, 5, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
    {"MC EU Narrow", 869618000, 625, 8, 8, 0x12, 32, PFL_CRC, LP_MESHCORE},
    {"MT MediumFast", 869525000, 2500, 9, 5, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
    {"MT ShortFast", 869525000, 2500, 7, 5, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
    {"MC EU old", 869525000, 2500, 11, 5, 0x12, 16, PFL_CRC, LP_MESHCORE},
    {"MT LongSlow", 869462500, 1250, 12, 8, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
};

// US915 mesh presets (Meshtastic default channels + MeshCore US).
static const Profile PROFILES_US[] = {
    {"MT LongFast", 906875000, 2500, 11, 5, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
    {"MC US", 910525000, 625, 7, 5, 0x12, 32, PFL_CRC, LP_MESHCORE},
    {"MT MediumFast", 913125000, 2500, 9, 5, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
    {"MT ShortFast", 918875000, 2500, 7, 5, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
    {"MT LongSlow", 905312500, 1250, 12, 8, 0x2B, 16, PFL_CRC, LP_MESHTASTIC},
};

const char *regionName(Region r) { return r == REGION_US ? "US 915" : "EU 868"; }

const Profile *profiles(Region r, size_t &countOut) {
    if (r == REGION_US) {
        countOut = sizeof(PROFILES_US) / sizeof(PROFILES_US[0]);
        return PROFILES_US;
    }
    countOut = sizeof(PROFILES_EU) / sizeof(PROFILES_EU[0]);
    return PROFILES_EU;
}

} // namespace loramp

#endif
