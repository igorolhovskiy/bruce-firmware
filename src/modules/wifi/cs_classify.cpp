#include "cs_classify.h"

#include "oui_db.h"
#include <Arduino.h>
#include <ctype.h>
#include <globals.h>
#include <string.h>

namespace cs {

const char *confName(uint8_t c) { return c == CONF_HIGH ? "HIGH" : c == CONF_MED ? "MED" : "LOW"; }

static bool ciContains(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return false;
    for (const char *h = hay; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
            a++;
            b++;
        }
        if (!*b) return true;
    }
    return false;
}

static bool ciStartsWith(const char *s, const char *p) {
    if (!s || !p) return false;
    while (*p) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*p)) return false;
        s++;
        p++;
    }
    return true;
}

static Hit mk(const char *kind, const char *label, uint8_t conf) {
    Hit h;
    h.hit = true;
    strlcpy(h.kind, kind, sizeof(h.kind));
    strlcpy(h.label, label ? label : "", sizeof(h.label));
    h.conf = conf;
    return h;
}

// Camera SSID match reusing the shared config lists (same rule as the WiFi
// Camera detector: patterns minus the exclusion list).
static bool ssidCamera(const char *ssid) {
    if (!ssid || !ssid[0]) return false;
    for (const auto &ex : bruceConfig.camSsidExclude)
        if (ciContains(ssid, ex.c_str())) return false;
    for (const auto &pat : bruceConfig.camSsidPatterns)
        if (ciContains(ssid, pat.c_str())) return true;
    return false;
}

Hit classifyWifi(const uint8_t *mac, const char *ssid) {
    const OuiEntry *o = lookupOui(mac);
    if (o) {
        switch (o->klass) {
        case OUI_FLOCK: return mk("FLOCK", o->vendor, CONF_HIGH);
        case OUI_ALPR: return mk("ALPR", o->vendor, CONF_HIGH);
        case OUI_RING: return mk("RING", o->vendor, CONF_HIGH);
        case OUI_CAM: return mk("CAM", o->vendor, CONF_HIGH);
        case OUI_DRONE: return mk("DRONE", o->vendor, CONF_MED);
        default: break;
        }
    }
    // SSID-based (pentest APs, then camera-name patterns).
    if (ciStartsWith(ssid, "Pineapple_")) return mk("PINEAPPLE", ssid, CONF_MED);
    if (ciStartsWith(ssid, "pwned")) return mk("DEAUTHER", ssid, CONF_MED);
    if (ssidCamera(ssid)) {
        bool iot = o && o->klass == OUI_IOT;
        return mk("CAM", ssid, iot ? CONF_HIGH : CONF_MED);
    }
    return Hit{};
}

Hit classifyWifiBeacon(const uint8_t *frame, int len) {
    // Pwnagotchi beacons carry a JSON "pwnd_tot" field in their IEs.
    if (!frame || len <= 36) return Hit{};
    if (len > 512) len = 512;
    static const char KEY[] = "pwnd_tot";
    const int kl = sizeof(KEY) - 1;
    for (int i = 36; i + kl <= len; i++)
        if (memcmp(frame + i, KEY, kl) == 0) return mk("PWNAGOTCHI", "pwnd_tot", CONF_HIGH);
    return Hit{};
}

Hit classifyBle(const uint8_t *mac, uint8_t addrType, const char *name, uint16_t company,
                const uint16_t *svcUuids, size_t nSvc) {
    // (1) Service UUIDs - exact signatures first.
    for (size_t i = 0; i < nSvc; i++) {
        uint16_t u = svcUuids[i];
        if (u == 0x3081 || u == 0x3082 || u == 0x3083) return mk("FLIPPER", "Flipper", CONF_HIGH);
        if (u == 0xFD5A) return mk("TRACKER", "SmartTag", CONF_HIGH);
        if (u == 0xFEED || u == 0xFEEC) return mk("TRACKER", "Tile", CONF_MED);
        if (u == 0xFEAA) return mk("TRACKER", "FindMy", CONF_MED);
        if (u == 0xFD5F) return mk("META", "RayBanMeta", CONF_MED);
    }
    // (2) Manufacturer company ID.
    if (company != 0xFFFF) {
        if (company == 0x0E29) return mk("FLIPPER", "Flipper", CONF_HIGH);
        if (company == 0x01AB || company == 0x058E || company == 0x0D53 || company == 0x03C2)
            return mk("META", "Meta", CONF_MED);
    }
    // (3) MAC OUI on public addresses (camera/IoT/hacker vendors).
    if (addrType == 0) {
        const OuiEntry *o = lookupOui(mac);
        if (o) {
            if (o->klass == OUI_HACKER) return mk("FLIPPER", o->vendor, CONF_HIGH);
            if (o->klass == OUI_CAM || o->klass == OUI_RING) return mk("SPY", o->vendor, CONF_MED);
        }
    }
    // (4) Advertised name.
    if (name && name[0]) {
        if (ciContains(name, "flipper")) return mk("FLIPPER", name, CONF_MED);
        static const char *cam[] = {"cam", "ipc", "doorbell", "spy", "hidden", "dvr"};
        for (auto p : cam)
            if (ciContains(name, p)) return mk("SPY", name, CONF_MED);
    }
    return Hit{};
}

bool runCsClassifySelfTest() {
    Serial.println("[Watch] cs_classify self-test");
    bool ok = true;

    // WiFi: a Hikvision camera OUI (44:19:B6) -> CAM HIGH.
    uint8_t camMac[6] = {0x44, 0x19, 0xB6, 0x11, 0x22, 0x33};
    Hit w = classifyWifi(camMac, "");
    bool t1 = w.hit && strcmp(w.kind, "CAM") == 0 && w.conf == CONF_HIGH;
    // WiFi SSID: Pineapple.
    uint8_t rnd[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    Hit w2 = classifyWifi(rnd, "Pineapple_1A2B");
    bool t2 = w2.hit && strcmp(w2.kind, "PINEAPPLE") == 0;
    // WiFi exclusion: "Campus-WiFi" must NOT be a camera.
    Hit w3 = classifyWifi(rnd, "Campus-WiFi");
    bool t3 = !w3.hit;
    // BLE: Flipper service UUID.
    uint16_t svc[1] = {0x3082};
    Hit b = classifyBle(rnd, 1, "Flipper Zero", 0xFFFF, svc, 1);
    bool t4 = b.hit && strcmp(b.kind, "FLIPPER") == 0 && b.conf == CONF_HIGH;

    ok = t1 && t2 && t3 && t4;
    Serial.printf("[Watch] self-test %s (cam=%d pineapple=%d campus-excl=%d flipper=%d)\n",
                  ok ? "PASS" : "FAIL", t1, t2, t3, t4);
    return ok;
}

} // namespace cs
