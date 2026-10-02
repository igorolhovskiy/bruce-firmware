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

static Hit mk(const char *kind, const char *label, uint8_t conf, uint8_t why, uint16_t whyArg = 0) {
    Hit h;
    h.hit = true;
    strlcpy(h.kind, kind, sizeof(h.kind));
    strlcpy(h.label, label ? label : "", sizeof(h.label));
    h.conf = conf;
    h.why = why;
    h.whyArg = whyArg;
    return h;
}

// Camera SSID match reusing the shared config lists (same rule as the WiFi
// Camera detector: patterns minus the exclusion list). Returns the index of the
// matched pattern, or -1.
static int ssidCamera(const char *ssid) {
    if (!ssid || !ssid[0]) return -1;
    for (const auto &ex : bruceConfig.camSsidExclude)
        if (ciContains(ssid, ex.c_str())) return -1;
    int i = 0;
    for (const auto &pat : bruceConfig.camSsidPatterns) {
        if (ciContains(ssid, pat.c_str())) return i;
        i++;
    }
    return -1;
}

static const char *const BLE_CAM_WORDS[] = {"cam", "ipc", "doorbell", "spy", "hidden", "dvr"};

Hit classifyWifi(const uint8_t *mac, const char *ssid) {
    const OuiEntry *o = lookupOui(mac);
    if (o) {
        switch (o->klass) {
        case OUI_FLOCK: return mk("FLOCK", o->vendor, CONF_HIGH, WHY_WIFI_OUI, o->klass);
        case OUI_ALPR: return mk("ALPR", o->vendor, CONF_HIGH, WHY_WIFI_OUI, o->klass);
        case OUI_RING: return mk("RING", o->vendor, CONF_HIGH, WHY_WIFI_OUI, o->klass);
        case OUI_CAM: return mk("CAM", o->vendor, CONF_HIGH, WHY_WIFI_OUI, o->klass);
        case OUI_DRONE: return mk("DRONE", o->vendor, CONF_MED, WHY_WIFI_OUI, o->klass);
        default: break;
        }
    }
    // SSID-based (pentest APs, then camera-name patterns).
    if (ciStartsWith(ssid, "Pineapple_")) return mk("PINEAPPLE", ssid, CONF_MED, WHY_SSID_PINEAPPLE);
    if (ciStartsWith(ssid, "pwned")) return mk("DEAUTHER", ssid, CONF_MED, WHY_SSID_DEAUTHER);
    int pat = ssidCamera(ssid);
    if (pat >= 0) {
        bool iot = o && o->klass == OUI_IOT;
        return mk("CAM", ssid, iot ? CONF_HIGH : CONF_MED, iot ? WHY_SSID_CAM_IOT : WHY_SSID_CAM, pat);
    }
    return Hit{};
}

Hit classifyWifiBeacon(const uint8_t *frame, int len) {
    if (!frame || len <= 36) return Hit{};
    if (len > 512) len = 512;
    // Open Drone ID (ASTM F3411): the vendor signature FA-0B-BC-0D in a beacon
    // vendor-IE. Exact 4-byte match -> HIGH. (Full operator-location decode lives
    // in the dedicated Drone Remote ID detector; the watch only flags presence.)
    for (int i = 36; i + 4 <= len; i++)
        if (frame[i] == 0xFA && frame[i + 1] == 0x0B && frame[i + 2] == 0xBC && frame[i + 3] == 0x0D)
            return mk("DRONE", "OpenDroneID", CONF_HIGH, WHY_BEACON_DRONE);
    // Pwnagotchi beacons carry a JSON "pwnd_tot" field in their IEs.
    static const char KEY[] = "pwnd_tot";
    const int kl = sizeof(KEY) - 1;
    for (int i = 36; i + kl <= len; i++)
        if (memcmp(frame + i, KEY, kl) == 0) return mk("PWNAGOTCHI", "pwnd_tot", CONF_HIGH, WHY_BEACON_PWND);
    return Hit{};
}

Hit classifyBle(const uint8_t *mac, uint8_t addrType, const char *name, uint16_t company,
                const uint16_t *svcUuids, size_t nSvc) {
    // (1) Service UUIDs - exact signatures first.
    for (size_t i = 0; i < nSvc; i++) {
        uint16_t u = svcUuids[i];
        if (u == 0x3081 || u == 0x3082 || u == 0x3083)
            return mk("FLIPPER", "Flipper", CONF_HIGH, WHY_BLE_SVC, u);
        if (u == 0xFFFA) return mk("DRONE", "OpenDroneID", CONF_HIGH, WHY_BLE_SVC, u);
        if (u == 0xFD5A) return mk("TRACKER", "SmartTag", CONF_HIGH, WHY_BLE_SVC, u);
        if (u == 0xFEED || u == 0xFEEC) return mk("TRACKER", "Tile", CONF_MED, WHY_BLE_SVC, u);
        if (u == 0xFEAA) return mk("TRACKER", "FindMy", CONF_MED, WHY_BLE_SVC, u);
        if (u == 0xFD5F) return mk("META", "RayBanMeta", CONF_MED, WHY_BLE_SVC, u);
    }
    // (2) Manufacturer company ID.
    if (company != 0xFFFF) {
        if (company == 0x0E29) return mk("FLIPPER", "Flipper", CONF_HIGH, WHY_BLE_COMPANY, company);
        if (company == 0x01AB || company == 0x058E || company == 0x0D53 || company == 0x03C2)
            return mk("META", "Meta", CONF_MED, WHY_BLE_COMPANY, company);
    }
    // (3) MAC OUI on public addresses (camera/IoT/hacker vendors).
    if (addrType == 0) {
        const OuiEntry *o = lookupOui(mac);
        if (o) {
            if (o->klass == OUI_HACKER) return mk("FLIPPER", o->vendor, CONF_HIGH, WHY_BLE_OUI, o->klass);
            if (o->klass == OUI_CAM || o->klass == OUI_RING)
                return mk("SPY", o->vendor, CONF_MED, WHY_BLE_OUI, o->klass);
        }
    }
    // (4) Advertised name.
    if (name && name[0]) {
        if (ciContains(name, "flipper")) return mk("FLIPPER", name, CONF_MED, WHY_BLE_NAME_FLIPPER);
        for (size_t i = 0; i < sizeof(BLE_CAM_WORDS) / sizeof(BLE_CAM_WORDS[0]); i++)
            if (ciContains(name, BLE_CAM_WORDS[i])) return mk("SPY", name, CONF_MED, WHY_BLE_NAME_CAM, i);
    }
    return Hit{};
}

const char *kindDescription(const char *k) {
    if (!k) return "";
    if (!strcmp(k, "CAM")) return "IP / WiFi camera";
    if (!strcmp(k, "FLOCK")) return "Flock Safety plate-reader camera";
    if (!strcmp(k, "ALPR")) return "Automated licence-plate reader";
    if (!strcmp(k, "RING")) return "Ring / Amazon doorbell camera";
    if (!strcmp(k, "DRONE")) return "Drone / UAV";
    if (!strcmp(k, "TRACKER")) return "Item tracker (can follow you)";
    if (!strcmp(k, "SPY")) return "Possible hidden camera / spy gadget";
    if (!strcmp(k, "FLIPPER")) return "Flipper Zero / pentest tool";
    if (!strcmp(k, "META")) return "Meta smart glasses (camera)";
    if (!strcmp(k, "PINEAPPLE")) return "Hak5 WiFi Pineapple (rogue AP)";
    if (!strcmp(k, "DEAUTHER")) return "ESP8266 deauther (WiFi attack)";
    if (!strcmp(k, "PWNAGOTCHI")) return "Pwnagotchi (WiFi handshake grabber)";
    return "Unknown kind";
}

static const char *svcName(uint16_t u) {
    switch (u) {
    case 0x3081:
    case 0x3082:
    case 0x3083: return "Flipper Zero serial/RPC service";
    case 0xFD5A: return "Samsung SmartTag";
    case 0xFEED:
    case 0xFEEC: return "Tile tracker";
    case 0xFEAA: return "Google Eddystone/Find My Device beacon";
    case 0xFD5F: return "Meta / Ray-Ban Meta glasses";
    case 0xFFFA: return "ASTM Open Drone ID (Remote ID)";
    default: return "known signature";
    }
}

static const char *companyName(uint16_t c) {
    switch (c) {
    case 0x0E29: return "Flipper Devices Inc.";
    case 0x01AB:
    case 0x058E:
    case 0x0D53:
    case 0x03C2: return "Meta Platforms (Facebook/Oculus/Luxottica)";
    default: return "known vendor";
    }
}

void explainWhy(uint8_t why, uint16_t a, char *out, size_t n) {
    switch (why) {
    case WHY_WIFI_OUI:
        snprintf(out, n,
                 "Transmitter MAC prefix (OUI) belongs to a vendor in the %s class of the built-in "
                 "OUI database. Vendor match alone is strong evidence.",
                 ouiClassName(a));
        break;
    case WHY_SSID_PINEAPPLE:
        snprintf(out, n, "Network name starts with \"Pineapple_\", the default SSID of a Hak5 WiFi "
                         "Pineapple rogue access point.");
        break;
    case WHY_SSID_DEAUTHER:
        snprintf(out, n, "Network name starts with \"pwned\", the default SSID of the ESP8266 "
                         "Deauther attack firmware.");
        break;
    case WHY_SSID_CAM:
    case WHY_SSID_CAM_IOT: {
        const char *pat = a < bruceConfig.camSsidPatterns.size() ? bruceConfig.camSsidPatterns[a].c_str() : "?";
        snprintf(out, n, "Network name contains \"%s\" from the camera SSID pattern list%s", pat,
                 why == WHY_SSID_CAM_IOT
                     ? ", AND the MAC is an IoT vendor often used in cameras - so confidence is HIGH."
                     : ". Name only, MAC vendor unknown: could be a normal network named that way.");
        break;
    }
    case WHY_BEACON_PWND:
        snprintf(out, n, "Beacon carries the \"pwnd_tot\" JSON field that only Pwnagotchi broadcasts "
                         "(it advertises its handshake count to its peers).");
        break;
    case WHY_BEACON_DRONE:
        snprintf(out, n, "Frame carries the ASTM Open Drone ID signature (FA-0B-BC-0D) - a drone "
                         "broadcasting Remote ID. Open the Drone Remote ID detector for full decode.");
        break;
    case WHY_BLE_SVC:
        snprintf(out, n, "BLE advert lists service UUID 0x%04X = %s.", a, svcName(a));
        break;
    case WHY_BLE_COMPANY:
        snprintf(out, n, "BLE manufacturer data carries company ID 0x%04X = %s.", a, companyName(a));
        break;
    case WHY_BLE_OUI:
        snprintf(out, n,
                 "Public (fixed) BLE address whose prefix belongs to a vendor in the %s class of the "
                 "OUI database.",
                 ouiClassName(a));
        break;
    case WHY_BLE_NAME_FLIPPER:
        snprintf(out, n, "Advertised BLE name contains \"flipper\". Names can be changed, so this is "
                         "medium confidence.");
        break;
    case WHY_BLE_NAME_CAM:
        snprintf(out, n,
                 "Advertised BLE name contains \"%s\", a word typical of camera / spy gadgets. "
                 "Name only, so medium confidence.",
                 a < sizeof(BLE_CAM_WORDS) / sizeof(BLE_CAM_WORDS[0]) ? BLE_CAM_WORDS[a] : "?");
        break;
    default: snprintf(out, n, "No rule recorded."); break;
    }
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
    // WiFi beacon: Open Drone ID vendor signature FA-0B-BC-0D in the body.
    uint8_t dframe[48] = {0};
    dframe[40] = 0xFA;
    dframe[41] = 0x0B;
    dframe[42] = 0xBC;
    dframe[43] = 0x0D;
    Hit d = classifyWifiBeacon(dframe, sizeof(dframe));
    bool t5 = d.hit && strcmp(d.kind, "DRONE") == 0 && d.conf == CONF_HIGH;

    ok = t1 && t2 && t3 && t4 && t5;
    Serial.printf("[Watch] self-test %s (cam=%d pineapple=%d campus-excl=%d flipper=%d drone=%d)\n",
                  ok ? "PASS" : "FAIL", t1, t2, t3, t4, t5);
    return ok;
}

} // namespace cs
