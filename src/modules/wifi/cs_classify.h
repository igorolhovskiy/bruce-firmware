#ifndef __CS_CLASSIFY_H__
#define __CS_CLASSIFY_H__

#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Counter-Surveil shared classifiers. One decision per received frame/advert,
// keyed off the shared oui_db + the signature sets below, so the Ambient Watch
// (and, over time, the individual detectors) share one source of truth instead
// of duplicating tables. Pure logic - no radio/display, unit-testable.
// Confidence: 0 = LOW, 1 = MED, 2 = HIGH. See bruce-ambient-watch-TASK.md.
// Signature data reuses oui_db (cameras/ALPR/Flock/Ring/Flipper) and the small
// BLE/pentest sets adapted from skizzophrenic/SquachWatch-CYD (GPL-3.0).
// ---------------------------------------------------------------------------

namespace cs {

enum Conf : uint8_t { CONF_LOW = 0, CONF_MED = 1, CONF_HIGH = 2 };

// Which rule produced a hit, so a UI can say *why* a device is listed.
// `whyArg` qualifies it: an OuiClass, a 16-bit service UUID, a BLE company ID,
// or an index into the matched SSID/name pattern list.
enum Why : uint8_t {
    WHY_NONE = 0,
    WHY_WIFI_OUI,       // arg = OuiClass of the transmitter MAC prefix
    WHY_SSID_PINEAPPLE, // SSID starts "Pineapple_"
    WHY_SSID_DEAUTHER,  // SSID starts "pwned"
    WHY_SSID_CAM,       // arg = index into bruceConfig.camSsidPatterns
    WHY_SSID_CAM_IOT,   // as above, plus the MAC is a known IoT vendor
    WHY_BEACON_PWND,    // beacon carries Pwnagotchi's "pwnd_tot" field
    WHY_BEACON_DRONE,   // frame carries the ASTM Open Drone ID vendor signature
    WHY_BLE_SVC,        // arg = 16-bit service UUID
    WHY_BLE_COMPANY,    // arg = manufacturer company ID
    WHY_BLE_OUI,        // arg = OuiClass of a public BLE address
    WHY_BLE_NAME_FLIPPER,
    WHY_BLE_NAME_CAM, // arg = index into the camera-name word list
};

struct Hit {
    bool hit = false;
    char kind[12] = {0};  // CAM / FLOCK / ALPR / RING / DRONE / TRACKER / SPY /
                          // FLIPPER / META / PINEAPPLE / DEAUTHER / PWNAGOTCHI
    char label[28] = {0}; // vendor / ssid / name
    uint8_t conf = CONF_LOW;
    uint8_t why = WHY_NONE;
    uint16_t whyArg = 0;
};

// WiFi management frame: classify by MAC OUI + SSID (camera vendors/patterns,
// ALPR/Flock/Ring, Hak5 Pineapple, ESP deauther). `ssid` may be "".
Hit classifyWifi(const uint8_t *mac, const char *ssid);

// WiFi beacon body: Pwnagotchi advertises a "pwnd_tot" field no normal AP has.
Hit classifyWifiBeacon(const uint8_t *frame, int len);

// BLE advertisement: classify by MAC OUI (public addrs) + manufacturer company
// ID + 16-bit service UUIDs + advertised name.
Hit classifyBle(const uint8_t *mac, uint8_t addrType, const char *name, uint16_t company,
                const uint16_t *svcUuids, size_t nSvc);

const char *confName(uint8_t c);

// Plain-English explanation of a hit's rule (why + whyArg), for detail views.
void explainWhy(uint8_t why, uint16_t whyArg, char *out, size_t outsz);

// What a threat kind ("CAM", "FLOCK", ...) actually is, in a few words.
const char *kindDescription(const char *kind);

// ── Stale ("passed by") threshold ───────────────────────────────────────────
// A listed device not heard for this long is drawn grey and sorted below the
// live ones, so things that were merely on the way (a car, a passer-by's phone)
// stop drawing attention while staying in the list for reference. Session-wide
// and shared by every Detector tool; cycled in Ambient Watch with 'g'.
// Default 2 min - see the rationale next to STALE_STEPS in cs_classify.cpp.
uint32_t staleMs(); // 0 = greying off
const char *staleName();
void cycleStale();
inline bool isStale(uint32_t lastMs, uint32_t now) {
    uint32_t s = staleMs();
    return s && now - lastMs > s;
}

// Offline self-test (serial-mirrored). Returns true on pass.
bool runCsClassifySelfTest();

} // namespace cs

#endif // __CS_CLASSIFY_H__
