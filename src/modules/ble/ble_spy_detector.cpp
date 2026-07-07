#include "ble_spy_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "modules/ble/ble_common.h"
#include "modules/wifi/oui_db.h"
#include <ctype.h>
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive BLE spy-gadget detector (sibling of tracker_detector, which is left
// intact). Continuous *passive* scan (no scan requests). Each advertisement is
// classified as a possible surveillance gadget via three heuristics:
//   1. Public/static BLE address whose OUI hits the shared vendor DB (oui_db) as
//      a camera / drone / IoT vendor.
//   2. Advertised device NAME matching a camera/doorbell/recorder pattern.
//   3. Manufacturer company-ID matching a small BLE gadget-vendor table.
// These are heuristics, not proof - confidence (H/M/L) and the matched class are
// shown per row so the user can judge. De-duplicated table sorted by signal;
// serial mirror + SD log. Existing AirTag/SmartTag/Tile detection stays in the
// Tracker Detector entry.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

enum Conf : uint8_t { CONF_LOW = 0, CONF_MED = 1, CONF_HIGH = 2 };
const char *confName(uint8_t c) { return c == CONF_HIGH ? "HIGH" : c == CONF_MED ? "MED" : "LOW"; }

// Small, extensible BLE manufacturer company-ID table for gadget vendors that are
// predominantly cameras / recorders. Kept deliberately tiny to avoid flagging
// every phone/watch; extend as needed.
struct BleSig {
    uint16_t company;
    const char *vendor;
    uint8_t klass;
};
const BleSig BLE_SIGS[] = {
    {0x0171, "Amazon/Ring", OUI_CAM},
    {0x0157, "Huami", OUI_IOT},
    {0x05A7, "Sonos", OUI_IOT},
};
constexpr size_t N_BLE_SIGS = sizeof(BLE_SIGS) / sizeof(BLE_SIGS[0]);

// Device-name substrings suggesting a camera / doorbell / recorder.
const char *NAME_PATTERNS[] = {
    "cam",  "ipc",  "reolink", "wyze",   "tapo",  "ezviz", "doorbell",
    "spy",  "hidden", "dvr",   "record", "audio", "bug",   "gimbal",
};
constexpr size_t N_NAME_PATTERNS = sizeof(NAME_PATTERNS) / sizeof(NAME_PATTERNS[0]);

bool ciContains(const char *hay, const char *needle) {
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

bool nameMatches(const char *name) {
    if (!name || !name[0]) return false;
    for (size_t i = 0; i < N_NAME_PATTERNS; i++)
        if (ciContains(name, NAME_PATTERNS[i])) return true;
    return false;
}

// Parse "aa:bb:cc:dd:ee:ff" -> 6 bytes. Returns false if malformed.
bool parseAddr(const char *s, uint8_t *out) {
    int vals[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)vals[i];
    return true;
}

// ── Sighting (callback -> ring) ──────────────────────────────────────────────
struct Sighting {
    char addr[18];
    uint8_t addrType;
    int8_t rssi;
    uint8_t klass;
    uint8_t conf;
    char vendor[20];
    char name[24];
};

constexpr size_t RING_SZ = 48;
Sighting ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;

void ringPush(const Sighting &s) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = s;
    ringHead = next;
}
bool ringPop(Sighting &s) {
    if (ringTail == ringHead) return false;
    s = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

// Extract the advertised name (AD 0x08/0x09) from a raw payload.
void extractName(const uint8_t *pl, size_t n, char *out, size_t outsz) {
    out[0] = 0;
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > n) break;
        uint8_t t = pl[i + 1];
        if (t == 0x08 || t == 0x09) {
            size_t dl = len - 1;
            size_t j = 0;
            for (size_t k = 0; k < dl && j + 1 < outsz; k++) {
                uint8_t c = pl[i + 2 + k];
                if (c >= 0x20 && c < 0x7f) out[j++] = (char)c;
            }
            out[j] = 0;
            return;
        }
        i += 1 + len;
    }
}

// Extract the manufacturer company ID (AD 0xFF, first 2 bytes LE). Returns 0xFFFF
// if none present.
uint16_t extractCompany(const uint8_t *pl, size_t n) {
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > n) break;
        uint8_t t = pl[i + 1];
        if (t == 0xFF && len >= 3) return (uint16_t)(pl[i + 2] | (pl[i + 3] << 8));
        i += 1 + len;
    }
    return 0xFFFF;
}

// Classify an advertisement. Returns true (and fills s.klass/conf/vendor) if it
// looks like a possible spy gadget.
bool classify(const uint8_t *addr, uint8_t addrType, const char *name, uint16_t company, Sighting &s) {
    bool hit = false;
    uint8_t conf = CONF_LOW;
    uint8_t klass = OUI_NONE;
    const char *vendor = "?";

    // (1) OUI DB on the address (public/static addresses only - random addresses
    //     have no meaningful vendor prefix).
    if (addrType == 0 /*public*/ || addrType == 1 /*random static top bits 11*/) {
        const OuiEntry *o = lookupOui(addr);
        if (o && (o->klass == OUI_CAM || o->klass == OUI_DRONE || o->klass == OUI_IOT)) {
            hit = true;
            klass = o->klass;
            vendor = o->vendor;
            conf = o->klass == OUI_CAM ? CONF_HIGH : CONF_MED;
        }
    }
    // (2) BLE company-ID table.
    if (company != 0xFFFF) {
        for (size_t i = 0; i < N_BLE_SIGS; i++)
            if (BLE_SIGS[i].company == company) {
                hit = true;
                if (klass == OUI_NONE) klass = BLE_SIGS[i].klass;
                if (vendor[0] == '?') vendor = BLE_SIGS[i].vendor;
                if (conf < CONF_MED) conf = CONF_MED;
                break;
            }
    }
    // (3) Device-name pattern.
    if (nameMatches(name)) {
        hit = true;
        if (klass == OUI_NONE) klass = OUI_CAM;
        if (conf < CONF_MED) conf = CONF_MED;
    }

    if (!hit) return false;
    s.klass = klass;
    s.conf = conf;
    strlcpy(s.vendor, vendor, sizeof(s.vendor));
    return true;
}

class SpyCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *dev) override {
        const std::vector<uint8_t> &pl = dev->getPayload();
        char name[24];
        extractName(pl.data(), pl.size(), name, sizeof(name));
        uint16_t company = extractCompany(pl.data(), pl.size());

        uint8_t addrBytes[6];
        String addrStr = dev->getAddress().toString().c_str();
        bool haveBytes = parseAddr(addrStr.c_str(), addrBytes);
        uint8_t addrType = dev->getAddressType();

        Sighting s = {};
        if (!haveBytes) return;
        if (!classify(addrBytes, addrType, name, company, s)) return;
        strlcpy(s.addr, addrStr.c_str(), sizeof(s.addr));
        s.addrType = addrType;
        s.rssi = dev->getRSSI();
        strlcpy(s.name, name, sizeof(s.name));
        ringPush(s);
    }
};

// ── Table ────────────────────────────────────────────────────────────────────
struct SpyEnt {
    char addr[18];
    char vendor[20];
    char name[24];
    uint8_t klass;
    uint8_t conf;
    int8_t rssi, bestRssi;
    uint16_t count;
    uint32_t firstMs, lastMs;
};
constexpr size_t SPY_MAX = 128;
std::vector<SpyEnt> spies;
int scroll = 0;

// ── SD logging ───────────────────────────────────────────────────────────────
bool spySd = false;
const char *DET_DIR = "/BruceDetector";
const char *SPY_CSV = "/BruceDetector/ble_spy.csv";
String nowClk() {
    if (clock_set) {
        struct tm t = rtc.getTimeStruct();
        char b[9];
        snprintf(b, sizeof(b), "%02d:%02d:%02d", t.tm_hour, t.tm_min, t.tm_sec);
        return String(b);
    }
    uint32_t s = millis() / 1000;
    char b[16];
    snprintf(b, sizeof(b), "+%02u:%02u:%02u", (unsigned)(s / 3600), (unsigned)((s / 60) % 60),
             (unsigned)(s % 60));
    return String(b);
}
void logSighting(const Sighting &s) {
    if (!spySd) return;
    File f = SD.open(SPY_CSV, FILE_APPEND);
    if (!f) return;
    f.println(
        String(millis()) + "," + nowClk() + "," + s.addr + "," + ouiClassName(s.klass) + "," + s.vendor +
        ",\"" + String(s.name) + "\"," + String(s.rssi) + "," + confName(s.conf)
    );
    f.close();
}

void onSighting(const Sighting &s) {
    for (auto &e : spies) {
        if (strcmp(e.addr, s.addr) == 0) {
            e.rssi = s.rssi;
            if (s.rssi > e.bestRssi) e.bestRssi = s.rssi;
            e.lastMs = millis();
            if (e.count < 0xFFFF) e.count++;
            if (s.conf > e.conf) e.conf = s.conf;
            if (e.name[0] == 0 && s.name[0]) strlcpy(e.name, s.name, sizeof(e.name));
            if (s.klass != OUI_NONE) e.klass = s.klass;
            logSighting(s);
            return;
        }
    }
    if (spies.size() >= SPY_MAX) {
        size_t oldest = 0;
        for (size_t i = 1; i < spies.size(); i++)
            if (spies[i].lastMs < spies[oldest].lastMs) oldest = i;
        spies.erase(spies.begin() + oldest);
    }
    SpyEnt e = {};
    strlcpy(e.addr, s.addr, sizeof(e.addr));
    strlcpy(e.vendor, s.vendor, sizeof(e.vendor));
    strlcpy(e.name, s.name, sizeof(e.name));
    e.klass = s.klass;
    e.conf = s.conf;
    e.rssi = e.bestRssi = s.rssi;
    e.count = 1;
    e.firstMs = e.lastMs = millis();
    spies.push_back(e);
    logSighting(s);
    Serial.printf(
        "[BleSpy] HIT %s class=%s vendor=%s name=\"%s\" rssi=%d conf=%s\n", s.addr,
        ouiClassName(s.klass), s.vendor, s.name, s.rssi, confName(s.conf)
    );
}

// ── Rendering (per-row diffed) ───────────────────────────────────────────────
constexpr int CHROME_H = 26;
constexpr int FOOTER_H = 12;
constexpr int ROW_H = 11;
constexpr int MAX_ROWS = 18;
String rowCache[MAX_ROWS];
uint16_t rowFgCache[MAX_ROWS];
String chromeCache[2];
String footerCache;
bool fullClear = true;

void resetCache() {
    for (int i = 0; i < MAX_ROWS; i++) {
        rowCache[i] = "\x01";
        rowFgCache[i] = 0xDEAD;
    }
    chromeCache[0] = chromeCache[1] = "\x01";
    footerCache = "\x01";
}
void drawRow(int slot, int y, const String &text, uint16_t fg) {
    if (slot < 0 || slot >= MAX_ROWS) return;
    if (rowCache[slot] == text && rowFgCache[slot] == fg) return;
    rowCache[slot] = text;
    rowFgCache[slot] = fg;
    tft.fillRect(0, y - 1, tftWidth, ROW_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(fg, TFT_BLACK);
    tft.drawString(text, 4, y);
}
int highConfCount() {
    int c = 0;
    for (auto &e : spies)
        if (e.conf == CONF_HIGH) c++;
    return c;
}
void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(l0, sizeof(l0), "BLE Spy Tags  drop:%lu", (unsigned long)ringDropped);
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    int hi = highConfCount();
    char l1[64];
    snprintf(l1, sizeof(l1), "gadgets:%u  high:%d", (unsigned)spies.size(), hi);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(hi > 0 ? TFT_RED : (spies.empty() ? TFT_GREEN : TFT_YELLOW), TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter() {
    String hint = "^v scroll  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}
void drawBody() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    std::vector<int> idx(spies.size());
    for (size_t i = 0; i < spies.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) { return spies[a].bestRssi > spies[b].bestRssi; });

    int total = (int)idx.size();
    int maxScroll = total - rows;
    if (maxScroll < 0) maxScroll = 0;
    if (scroll > maxScroll) scroll = maxScroll;
    if (scroll < 0) scroll = 0;

    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int li = scroll + slot;
        if (li >= total) {
            if (total == 0 && slot == 0) drawRow(slot, y, "  (listening for BLE gadgets...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const SpyEnt &e = spies[idx[li]];
        char cflag = e.conf == CONF_HIGH ? 'H' : e.conf == CONF_MED ? 'M' : 'L';
        String label = e.name[0] ? String(e.name) : String(e.vendor);
        if (label.length() > 14) label = label.substring(0, 14);
        String line = String(cflag) + " " + String(ouiClassName(e.klass)) + " " + label + " " +
                      String(e.rssi) + " x" + String(e.count) + " " + String(e.addr).substring(9);
        uint16_t fg = e.conf == CONF_HIGH ? TFT_RED : e.conf == CONF_MED ? TFT_YELLOW : TFT_DARKGREY;
        drawRow(slot, y, line, fg);
    }
}
void spyDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome();
    drawBody();
    drawFooter();
}

} // namespace

void ble_spy_detector() {
    Serial.println("[BleSpy] passive BLE spy-gadget detector starting (RX-only)");
    spies.clear();
    ringHead = ringTail = ringDropped = 0;
    scroll = 0;
    fullClear = true;

    spySd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(DET_DIR)) SD.mkdir(DET_DIR);
        spySd = true;
        if (!SD.exists(SPY_CSV)) {
            File f = SD.open(SPY_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,clock,addr,class,vendor,name,rssi,confidence");
                f.close();
            }
        }
        Serial.printf("[BleSpy] logging -> %s\n", SPY_CSV);
    } else {
        Serial.println("[BleSpy] no SD card - logging disabled");
    }

    ble_scan_setup(); // WiFi teardown + BLEDevice::init
    pBLEScan->setScanCallbacks(new SpyCallbacks(), true);
    pBLEScan->setActiveScan(false);
    pBLEScan->setMaxResults(0);
    pBLEScan->start(0, false);

    spyDraw();

    while (!check(EscPress)) {
        Sighting s;
        int drained = 0;
        while (drained++ < 32 && ringPop(s)) onSighting(s);

        if (check(PrevPress) && scroll > 0) scroll--;
        if (check(NextPress)) scroll++;

        spyDraw();
        delay(20);
    }

    pBLEScan->stop();
    stopBLEStack();
    Serial.printf(
        "[BleSpy] stopped. gadgets=%u dropped=%lu\n", (unsigned)spies.size(),
        (unsigned long)ringDropped
    );
}
