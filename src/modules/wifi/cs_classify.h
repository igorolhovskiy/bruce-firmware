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

struct Hit {
    bool hit = false;
    char kind[12] = {0};  // CAM / FLOCK / ALPR / RING / DRONE / TRACKER / SPY /
                          // FLIPPER / META / PINEAPPLE / DEAUTHER / PWNAGOTCHI
    char label[28] = {0}; // vendor / ssid / name
    uint8_t conf = CONF_LOW;
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

// Offline self-test (serial-mirrored). Returns true on pass.
bool runCsClassifySelfTest();

} // namespace cs

#endif // __CS_CLASSIFY_H__
