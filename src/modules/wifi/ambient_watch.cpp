#include "ambient_watch.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "cs_classify.h"
#include "modules/ble/ble_common.h"
#include "oui_db.h"
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <algorithm>
#include <stdarg.h>
#include <esp_wifi.h>
#include <globals.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Ambient Watch (bruce-ambient-watch-TASK.md, Phase 1). One passive scan that
// time-slices the radio: a BLE phase, then a WiFi-promiscuous phase (channel
// hopping), looping. Each phase feeds cs::classify*() hits into one de-duplicated
// threat table. Flicker-free per-row UI, serial mirror. Receive-only; restores
// WiFi mode on exit. The time-sliced "watch" + confidence model is adapted from
// skizzophrenic/SquachWatch-CYD (GPL-3.0, AGPL-compatible via section 13).
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// ── Unified threat event (callback -> ring) ──────────────────────────────────
// Besides the hit itself, an event carries the raw evidence (SSID / BLE name,
// channel, frame type, BLE company + service UUIDs) for the details view.
enum FrameType : uint8_t { FR_PROBE_REQ = 0, FR_BEACON, FR_PROBE_RESP, FR_BLE_ADV };
constexpr size_t MAX_SVC = 4;
struct Event {
    char addr[18];
    char name[33]; // WiFi SSID / BLE advertised name ("" if none)
    int8_t rssi;
    bool ble;
    uint8_t ch;    // WiFi channel (0 for BLE)
    uint8_t frame; // FrameType
    uint8_t addrType;
    uint8_t nSvc;
    uint16_t company; // 0xFFFF = none
    uint16_t svc[MAX_SVC];
    cs::Hit hit;
};
// The ring lives in PSRAM next to the threat table (see allocThreats): with the
// evidence fields it is ~5 KB, too much to park in internal RAM.
constexpr size_t RING_SZ = 48;
Event *ring = nullptr;
volatile uint16_t ringHead = 0, ringTail = 0;
volatile uint32_t ringDropped = 0;

void ringPush(const Event &e) {
    if (!ring) return;
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(Event &e) {
    if (!ring || ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

void macStr(const uint8_t *m, char *out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

// ── WiFi phase ───────────────────────────────────────────────────────────────
const uint8_t wifi_channels[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
constexpr size_t N_WIFI_CH = sizeof(wifi_channels);
volatile uint32_t wifiFrames = 0;

void extractSsid(const uint8_t *p, int len, int off, char *out) {
    out[0] = 0;
    int o = off;
    while (o + 2 <= len) {
        uint8_t tag = p[o], tl = p[o + 1];
        if (o + 2 + tl > len) break;
        if (tag == 0) {
            int n = tl > 32 ? 32 : tl, j = 0;
            for (int i = 0; i < n; i++) {
                uint8_t c = p[o + 2 + i];
                if (c >= 0x20 && c < 0x7f) out[j++] = (char)c;
            }
            out[j] = 0;
            return;
        }
        o += 2 + tl;
    }
}

void wifi_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;
    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 0) return;
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    const uint8_t *mac;
    char ssid[33] = {0};
    bool beacon = false;
    uint8_t frame;
    if (subtype == 0x04) {
        mac = p + 10;
        extractSsid(p, len, 24, ssid);
        frame = FR_PROBE_REQ;
    } else if (subtype == 0x08 || subtype == 0x05) {
        mac = p + 16;
        extractSsid(p, len, 36, ssid);
        beacon = true;
        frame = subtype == 0x08 ? FR_BEACON : FR_PROBE_RESP;
    } else {
        return;
    }
    wifiFrames = wifiFrames + 1;

    cs::Hit h = cs::classifyWifi(mac, ssid);
    if (!h.hit && beacon) h = cs::classifyWifiBeacon(p, len);
    if (!h.hit) return;

    Event e = {};
    macStr(mac, e.addr);
    strlcpy(e.name, ssid, sizeof(e.name));
    e.rssi = pkt->rx_ctrl.rssi;
    e.ble = false;
    e.ch = pkt->rx_ctrl.channel;
    e.frame = frame;
    e.company = 0xFFFF;
    e.hit = h;
    ringPush(e);
}

// ── BLE phase ────────────────────────────────────────────────────────────────
void bleExtractName(const uint8_t *pl, size_t n, char *out, size_t outsz) {
    out[0] = 0;
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > n) break;
        uint8_t t = pl[i + 1];
        if (t == 0x08 || t == 0x09) {
            size_t dl = len - 1, j = 0;
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
uint16_t bleExtractCompany(const uint8_t *pl, size_t n) {
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > n) break;
        if (pl[i + 1] == 0xFF && len >= 3) return (uint16_t)(pl[i + 2] | (pl[i + 3] << 8));
        i += 1 + len;
    }
    return 0xFFFF;
}
size_t bleExtractSvc(const uint8_t *pl, size_t n, uint16_t *out, size_t cap) {
    size_t cnt = 0, i = 0;
    while (i + 1 < n) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > n) break;
        uint8_t t = pl[i + 1];
        if ((t == 0x02 || t == 0x03) && len >= 3) {
            for (size_t off = 2; off + 1 < (size_t)(len + 1) && cnt < cap; off += 2)
                out[cnt++] = (uint16_t)(pl[i + off] | (pl[i + off + 1] << 8));
        }
        i += 1 + len;
    }
    return cnt;
}

class WatchBleCb : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *dev) override {
        const std::vector<uint8_t> &pl = dev->getPayload();
        char name[33];
        bleExtractName(pl.data(), pl.size(), name, sizeof(name));
        uint16_t company = bleExtractCompany(pl.data(), pl.size());
        uint16_t svc[8];
        size_t nSvc = bleExtractSvc(pl.data(), pl.size(), svc, 8);

        uint8_t mac[6] = {0};
        String a = dev->getAddress().toString().c_str();
        int v[6];
        if (sscanf(a.c_str(), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6)
            for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
        uint8_t at = dev->getAddressType();

        cs::Hit h = cs::classifyBle(mac, at, name, company, svc, nSvc);
        if (!h.hit) return;
        Event e = {};
        strlcpy(e.addr, a.c_str(), sizeof(e.addr));
        strlcpy(e.name, name, sizeof(e.name));
        e.rssi = dev->getRSSI();
        e.ble = true;
        e.frame = FR_BLE_ADV;
        e.addrType = at;
        e.company = company;
        e.nSvc = nSvc > MAX_SVC ? MAX_SVC : nSvc;
        for (size_t i = 0; i < e.nSvc; i++) e.svc[i] = svc[i];
        e.hit = h;
        ringPush(e);
    }
};
WatchBleCb bleCb;

// ── Threat table ─────────────────────────────────────────────────────────────
struct Threat {
    char addr[18];
    char kind[12];
    char label[28];
    char name[33]; // last non-empty SSID / BLE name seen
    uint8_t conf;
    uint8_t why;
    uint16_t whyArg;
    bool ble;
    int8_t rssi, bestRssi, worstRssi;
    int32_t rssiSum;
    uint16_t count;
    uint32_t firstMs, lastMs;
    uint8_t ch, frame, addrType, nSvc;
    uint16_t chMask; // bit n = heard on WiFi channel n
    uint16_t company;
    uint16_t svc[MAX_SVC];
};
// The threat table lives in PSRAM where the board has it. Once the BLE stack is
// up, the T-Deck's *internal* heap is down to ~9 KB (NimBLE costs ~106 KB), and
// Arduino keeps allocations under 4 KB internal even with PSRAM fitted. A growing
// std::vector<Threat> had to hold the old and new buffers side by side on that
// heap while doubling -- ~11 KB for the last step. That allocation fails, and a
// failed operator new calls abort(), which is what rebooted the device back to
// the main menu part-way through a watch. One fixed block never reallocs, and in
// PSRAM it costs the internal heap nothing.
constexpr size_t THREAT_MAX = 96;
Threat *threats = nullptr;
size_t threatCount = 0;
int cursor = 0, scroll = 0;

// Details view text, rebuilt per frame (also PSRAM: ~2 KB).
constexpr int DL_MAX = 36;
constexpr size_t DL_SZ = 56;
char (*dLines)[DL_SZ] = nullptr;

void *bigAlloc(size_t bytes) {
    void *p = psramFound() ? ps_malloc(bytes) : malloc(bytes);
    if (p) memset(p, 0, bytes);
    return p;
}
void freeThreats() {
    free(threats);
    free(ring);
    free(dLines);
    threats = nullptr;
    ring = nullptr;
    dLines = nullptr;
    threatCount = 0;
}
bool allocThreats() {
    if (!threats) threats = (Threat *)bigAlloc(THREAT_MAX * sizeof(Threat));
    if (!ring) ring = (Event *)bigAlloc(RING_SZ * sizeof(Event));
    if (!dLines) dLines = (char (*)[DL_SZ])bigAlloc(DL_MAX * DL_SZ);
    if (threats && ring && dLines) return true;
    freeThreats();
    return false;
}

// ALERT FILTER: minimum confidence a hit needs to show in the list and raise the
// alert banner. Cycled with the 'f' key. Default MED so low-confidence noise stays quiet.
uint8_t alertFilter = cs::CONF_MED;
const char *filterName(uint8_t f) { return f == cs::CONF_HIGH ? "High" : f == cs::CONF_MED ? "Med+" : "All"; }

// Transient alert banner (set on a qualifying hit, auto-clears).
char alertKind[12] = {0};
char alertLabel[28] = {0};
int8_t alertRssi = 0;
uint32_t alertUntil = 0;
constexpr uint32_t ALERT_MS = 4000;

void raiseAlert(const Event &ev) {
    if (ev.hit.conf < alertFilter) return;
    strlcpy(alertKind, ev.hit.kind, sizeof(alertKind));
    strlcpy(alertLabel, ev.hit.label, sizeof(alertLabel));
    alertRssi = ev.rssi;
    alertUntil = millis() + ALERT_MS;
}

// Refresh the evidence fields of a row from its latest event.
void absorbEvidence(Threat &t, const Event &ev) {
    if (ev.name[0]) strlcpy(t.name, ev.name, sizeof(t.name));
    t.frame = ev.frame;
    if (ev.ble) {
        t.addrType = ev.addrType;
        if (ev.company != 0xFFFF) t.company = ev.company;
        if (ev.nSvc) {
            t.nSvc = ev.nSvc;
            for (size_t i = 0; i < ev.nSvc; i++) t.svc[i] = ev.svc[i];
        }
    } else if (ev.ch > 0 && ev.ch < 16) {
        t.ch = ev.ch;
        t.chMask |= (uint16_t)(1u << ev.ch);
    }
}

// ── SD logging (new threats only, to avoid flooding) ─────────────────────────
bool watchSd = false;
const char *WATCH_DIR = "/BruceDetector";
const char *WATCH_CSV = "/BruceDetector/watch.csv";
String watchClk() {
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
void watchSetupSd() {
    watchSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(WATCH_DIR)) SD.mkdir(WATCH_DIR);
        watchSd = true;
        if (!SD.exists(WATCH_CSV)) {
            File f = SD.open(WATCH_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,clock,band,addr,kind,label,rssi,confidence");
                f.close();
            }
        }
        Serial.printf("[Watch] logging -> %s\n", WATCH_CSV);
    } else {
        Serial.println("[Watch] no SD card - logging disabled");
    }
}
void logThreat(const Event &ev) {
    if (!watchSd) return;
    File f = SD.open(WATCH_CSV, FILE_APPEND);
    if (!f) return;
    f.println(String(millis()) + "," + watchClk() + "," + (ev.ble ? "BLE" : "WIFI") + "," + ev.addr +
              "," + ev.hit.kind + ",\"" + String(ev.hit.label) + "\"," + String(ev.rssi) + "," +
              cs::confName(ev.hit.conf));
    f.close();
}

void onEvent(const Event &ev) {
    raiseAlert(ev);
    if (!threats) return;
    for (size_t i = 0; i < threatCount; i++) {
        Threat &t = threats[i];
        if (t.ble == ev.ble && strcmp(t.addr, ev.addr) == 0 && strcmp(t.kind, ev.hit.kind) == 0) {
            t.rssi = ev.rssi;
            if (ev.rssi > t.bestRssi) t.bestRssi = ev.rssi;
            if (ev.rssi < t.worstRssi) t.worstRssi = ev.rssi;
            if (t.count < 0xFFFF) {
                t.count++;
                t.rssiSum += ev.rssi;
            }
            if (ev.hit.conf > t.conf) { // a stronger rule fired: it is now the reason
                t.conf = ev.hit.conf;
                t.why = ev.hit.why;
                t.whyArg = ev.hit.whyArg;
            }
            absorbEvidence(t, ev);
            t.lastMs = millis();
            return;
        }
    }
    size_t slot = threatCount;
    if (slot >= THREAT_MAX) { // table full: recycle the least recently seen row
        slot = 0;
        for (size_t i = 1; i < THREAT_MAX; i++)
            if (threats[i].lastMs < threats[slot].lastMs) slot = i;
    }
    Threat t = {};
    strlcpy(t.addr, ev.addr, sizeof(t.addr));
    strlcpy(t.kind, ev.hit.kind, sizeof(t.kind));
    strlcpy(t.label, ev.hit.label, sizeof(t.label));
    t.conf = ev.hit.conf;
    t.why = ev.hit.why;
    t.whyArg = ev.hit.whyArg;
    t.ble = ev.ble;
    t.rssi = t.bestRssi = t.worstRssi = ev.rssi;
    t.rssiSum = ev.rssi;
    t.count = 1;
    t.company = 0xFFFF;
    absorbEvidence(t, ev);
    t.firstMs = t.lastMs = millis();
    threats[slot] = t;
    if (threatCount < THREAT_MAX) threatCount++;
    logThreat(ev); // new threats only
    Serial.printf("[Watch] %s HIT %s %s \"%s\" rssi=%d conf=%s\n", ev.ble ? "BLE" : "WIFI", ev.hit.kind,
                  ev.addr, ev.hit.label, ev.rssi, cs::confName(ev.hit.conf));
}

// ── Rendering (per-row diffed) ───────────────────────────────────────────────
// Row/chrome caches are plain char buffers, and drawRow takes a const char*.
// They used to be Arduino Strings: every drawRow() call built a String temporary
// on the internal heap whether or not the row had changed -- ~1200 allocations a
// second against a 9 KB pool, fragmenting it under the threat table's growth.
// Now a repaint is the only thing that allocates (tft.drawString takes a String).
constexpr int CHROME_H = 26, FOOTER_H = 12, ROW_H = 11, MAX_ROWS = 18;
constexpr size_t ROW_CACHE_SZ = 56;
char rowCache[MAX_ROWS][ROW_CACHE_SZ];
uint16_t rowFgCache[MAX_ROWS];
char chromeCache[2][80];
const char *footerDrawn = nullptr; // hint currently on screen
bool fullClear = true;

// Details view state. The open row is pinned by slot AND identity (addr, kind,
// firstMs) so a slot recycled by a full table is noticed, not misreported.
bool detailOpen = false;
int detailSlot = -1;
char detailAddr[18], detailKind[12];
uint32_t detailFirstMs = 0;
int detailScroll = 0;

// Sorted, filtered view of the table as last drawn; maps cursor -> slot.
int16_t listIdx[THREAT_MAX];
int listTotal = 0;

void resetCache() {
    for (int i = 0; i < MAX_ROWS; i++) {
        rowCache[i][0] = '\x01'; // sentinel: matches no real row text
        rowCache[i][1] = 0;
        rowFgCache[i] = 0xDEAD;
    }
    for (int i = 0; i < 2; i++) {
        chromeCache[i][0] = '\x01';
        chromeCache[i][1] = 0;
    }
    footerDrawn = nullptr;
}
void drawRow(int slot, int y, const char *text, uint16_t fg) {
    if (slot < 0 || slot >= MAX_ROWS) return;
    if (strcmp(rowCache[slot], text) == 0 && rowFgCache[slot] == fg) return;
    strlcpy(rowCache[slot], text, ROW_CACHE_SZ);
    rowFgCache[slot] = fg;
    tft.fillRect(0, y - 1, tftWidth, ROW_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(fg, TFT_BLACK);
    tft.drawString(text, 4, y);
}
int highCount() {
    int c = 0;
    for (size_t i = 0; i < threatCount; i++)
        if (threats[i].conf == cs::CONF_HIGH) c++;
    return c;
}
bool g_resting = false; // REST duty-cycle phase: both radios idle

void drawChrome(bool blePhase, uint8_t ch) {
    tft.setTextSize(FP);
    char l0[64];
    if (g_resting) snprintf(l0, sizeof(l0), "Ambient Watch  [REST]");
    else if (blePhase) snprintf(l0, sizeof(l0), "Ambient Watch  [BLE] scan");
    else snprintf(l0, sizeof(l0), "Ambient Watch  [WIFI] ch%u", ch);
    if (strcmp(chromeCache[0], l0) != 0) {
        strlcpy(chromeCache[0], l0, sizeof(chromeCache[0]));
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    int hi = highCount();
    bool alerting = (int32_t)(millis() - alertUntil) < 0 && alertKind[0];
    char l1[72];
    uint16_t l1fg;
    if (alerting) {
        snprintf(l1, sizeof(l1), "! %s %s %d", alertKind, alertLabel, alertRssi);
        l1fg = TFT_RED;
    } else {
        snprintf(l1, sizeof(l1), "threats:%u high:%d filt:%s drop:%lu", (unsigned)threatCount, hi,
                 filterName(alertFilter), (unsigned long)ringDropped);
        l1fg = hi > 0 ? TFT_RED : (threatCount == 0 ? TFT_GREEN : TFT_YELLOW);
    }
    if (strcmp(chromeCache[1], l1) != 0) {
        strlcpy(chromeCache[1], l1, sizeof(chromeCache[1]));
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(l1fg, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter(const char *hint) {
    if (footerDrawn == hint) return;
    footerDrawn = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}
int bodyRows() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    return rows > MAX_ROWS ? MAX_ROWS : rows;
}

// ── Details view ─────────────────────────────────────────────────────────────
uint16_t dFg[DL_MAX];
int dCount = 0;
constexpr int DL_COLS = 52; // 6 px glyphs across 320 - 4 px margin

void dAdd(uint16_t fg, const char *fmt, ...) {
    if (dCount >= DL_MAX) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dLines[dCount], DL_SZ, fmt, ap);
    va_end(ap);
    dFg[dCount++] = fg;
}
// Word-wrap `text` into lines of DL_COLS, each prefixed by `indent` spaces.
void dWrap(uint16_t fg, const char *text, int indent) {
    int width = DL_COLS - indent;
    const char *p = text;
    while (*p && dCount < DL_MAX) {
        while (*p == ' ') p++;
        int n = strlen(p);
        if (n > width) {
            n = width;
            while (n > 0 && p[n] != ' ') n--;
            if (n == 0) n = width; // one unbreakable word
        }
        dAdd(fg, "%*s%.*s", indent, "", n, p);
        p += n;
    }
}
void fmtAgo(uint32_t ms, char *out, size_t n) {
    uint32_t s = ms / 1000;
    if (s < 60) snprintf(out, n, "%lus", (unsigned long)s);
    else if (s < 3600) snprintf(out, n, "%lum%02lus", (unsigned long)(s / 60), (unsigned long)(s % 60));
    else snprintf(out, n, "%luh%02lum", (unsigned long)(s / 3600), (unsigned long)(s / 60 % 60));
}
const char *proximity(int rssi) {
    if (rssi >= -50) return "very close (a few metres)";
    if (rssi >= -65) return "near (same room / ~10 m)";
    if (rssi >= -80) return "medium (~10-30 m)";
    return "far / behind walls";
}
const char *frameName(uint8_t f) {
    switch (f) {
    case FR_PROBE_REQ: return "probe request (client searching)";
    case FR_BEACON: return "beacon (access point)";
    case FR_PROBE_RESP: return "probe response (access point)";
    default: return "advertisement";
    }
}
const char *confMeaning(uint8_t c) {
    if (c == cs::CONF_HIGH) return "Strong, specific signature - very likely what it says.";
    if (c == cs::CONF_MED) return "Likely, but based on a name or a shared ID - verify.";
    return "Weak hint only - often a false positive.";
}
uint16_t confColor(uint8_t c) {
    return c == cs::CONF_HIGH ? TFT_RED : c == cs::CONF_MED ? TFT_YELLOW : TFT_DARKGREY;
}

void buildDetails() {
    dCount = 0;
    const Threat *tp = nullptr;
    if (detailSlot >= 0 && (size_t)detailSlot < threatCount) {
        const Threat &c = threats[detailSlot];
        if (c.firstMs == detailFirstMs && !strcmp(c.addr, detailAddr) && !strcmp(c.kind, detailKind)) tp = &c;
    }
    if (!tp) {
        dAdd(TFT_YELLOW, "%s %s", detailKind, detailAddr);
        dAdd(TFT_DARKGREY, "This record was recycled: the table filled up");
        dAdd(TFT_DARKGREY, "(%u rows) and it was the least recently seen.", (unsigned)THREAT_MAX);
        return;
    }
    const Threat &t = *tp;
    uint32_t now = millis();
    char buf[200];

    dAdd(confColor(t.conf), "%s  [%s]  via %s", t.kind, cs::confName(t.conf), t.ble ? "BLE" : "WiFi");
    dAdd(TFT_WHITE, " %s", cs::kindDescription(t.kind));

    uint8_t mac[6] = {0};
    unsigned v[6];
    bool macOk = sscanf(t.addr, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6;
    if (macOk)
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    if (t.ble)
        dAdd(TFT_WHITE, "Address : %s (%s)", t.addr,
             t.addrType == 0 ? "public" : t.addrType == 1 ? "random" : "other");
    else dAdd(TFT_WHITE, "Address : %s", t.addr);
    const OuiEntry *o = macOk ? lookupOui(mac) : nullptr;
    bool randomMac = t.ble ? t.addrType != 0 : (mac[0] & 0x02);
    if (o) dAdd(TFT_WHITE, "Vendor  : %.30s [%s]", o->vendor, ouiClassName(o->klass));
    else if (randomMac) dAdd(TFT_DARKGREY, "Vendor  : n/a (randomized / private address)");
    else dAdd(TFT_DARKGREY, "Vendor  : not in built-in OUI database");
    dAdd(TFT_WHITE, "Label   : %s", t.label);
    if (t.ble) dAdd(TFT_WHITE, "Name    : %s", t.name[0] ? t.name : "(not advertised)");
    else if (t.frame == FR_PROBE_REQ)
        dAdd(TFT_WHITE, "Looking : %s", t.name[0] ? t.name : "(any network / wildcard)");
    else dAdd(TFT_WHITE, "SSID    : %s", t.name[0] ? t.name : "(hidden)");

    if (t.ble) {
        if (t.company != 0xFFFF) dAdd(TFT_WHITE, "Company : 0x%04X (manufacturer data)", t.company);
        else dAdd(TFT_DARKGREY, "Company : none advertised");
        if (t.nSvc) {
            int n = snprintf(buf, sizeof(buf), "Services:");
            for (int i = 0; i < t.nSvc; i++) n += snprintf(buf + n, sizeof(buf) - n, " %04X", t.svc[i]);
            dAdd(TFT_WHITE, "%s", buf);
        } else dAdd(TFT_DARKGREY, "Services: none advertised (16-bit)");
        dAdd(TFT_WHITE, "Frame   : %s", frameName(t.frame));
    } else {
        int n = snprintf(buf, sizeof(buf), "Channel : %u  (heard on", t.ch);
        for (int c = 1; c < 16; c++)
            if (t.chMask & (1u << c)) n += snprintf(buf + n, sizeof(buf) - n, " %d", c);
        snprintf(buf + n, sizeof(buf) - n, ")");
        dAdd(TFT_WHITE, "%s", buf);
        dAdd(TFT_WHITE, "Frame   : %s", frameName(t.frame));
    }

    int avg = t.count ? (int)(t.rssiSum / t.count) : t.rssi;
    dAdd(TFT_CYAN, "RSSI dBm: now %d  best %d  worst %d  avg %d", t.rssi, t.bestRssi, t.worstRssi, avg);
    dAdd(TFT_CYAN, "Distance: %s", proximity(t.bestRssi));
    char first[16], last[16];
    fmtAgo(now - t.firstMs, first, sizeof(first));
    fmtAgo(now - t.lastMs, last, sizeof(last));
    dAdd(TFT_WHITE, "Seen    : %ux, first %s ago, last %s ago", t.count, first, last);
    if (now - t.lastMs > 60000)
        dAdd(TFT_DARKGREY, " (not heard for a while - out of range or off)");

    dAdd(TFT_DARKGREY, "--- Why it is on the list ---");
    cs::explainWhy(t.why, t.whyArg, buf, sizeof(buf));
    dWrap(TFT_YELLOW, buf, 1);
    dAdd(confColor(t.conf), "Confidence %s:", cs::confName(t.conf));
    dWrap(TFT_WHITE, confMeaning(t.conf), 1);
    if (t.ble && t.addrType != 0)
        dWrap(TFT_DARKGREY, "Random BLE addresses rotate every few minutes, so one device can appear "
                            "as several rows over time.", 1);
}

void drawDetails() {
    buildDetails();
    int rows = bodyRows();
    int maxScroll = dCount > rows ? dCount - rows : 0;
    if (detailScroll > maxScroll) detailScroll = maxScroll;
    if (detailScroll < 0) detailScroll = 0;
    for (int slot = 0; slot < rows; slot++) {
        int li = detailScroll + slot;
        int y = CHROME_H + slot * ROW_H;
        if (li < dCount) drawRow(slot, y, dLines[li], dFg[li]);
        else drawRow(slot, y, "", TFT_WHITE);
    }
    drawFooter(maxScroll ? "<-/b back  ^v scroll  (scan keeps running)" : "<-/b back  (scan keeps running)");
}

void awDraw(bool blePhase, uint8_t ch) {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome(blePhase, ch);
    if (detailOpen) {
        drawDetails();
        return;
    }
    int rows = bodyRows();

    int16_t *idx = listIdx;
    int total = 0;
    for (size_t i = 0; i < threatCount; i++)
        if (threats[i].conf >= alertFilter) idx[total++] = (int16_t)i; // ALERT FILTER gates the list
    std::sort(idx, idx + total, [&](int16_t a, int16_t b) {
        if (threats[a].conf != threats[b].conf) return threats[a].conf > threats[b].conf;
        return threats[a].bestRssi > threats[b].bestRssi;
    });
    if (cursor >= total) cursor = total ? total - 1 : 0;
    if (cursor < 0) cursor = 0;
    if (cursor < scroll) scroll = cursor;
    if (cursor >= scroll + rows) scroll = cursor - rows + 1;
    if (scroll > total - rows) scroll = total > rows ? total - rows : 0;
    if (scroll < 0) scroll = 0;

    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int li = scroll + slot;
        if (li >= total) {
            if (total == 0 && slot == 0) drawRow(slot, y, "  (watching WiFi + BLE...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const Threat &t = threats[idx[li]];
        char cflag = t.conf == cs::CONF_HIGH ? 'H' : t.conf == cs::CONF_MED ? 'M' : 'L';
        char line[ROW_CACHE_SZ];
        snprintf(line, sizeof(line), "%c%c %s %.14s %d x%u", li == cursor ? '>' : ' ', cflag,
                 t.kind, t.label, t.rssi, t.count);
        uint16_t fg = li == cursor            ? TFT_CYAN
                      : t.conf == cs::CONF_HIGH ? TFT_RED
                      : t.conf == cs::CONF_MED  ? TFT_YELLOW
                                                : TFT_DARKGREY;
        drawRow(slot, y, line, fg);
    }
    listTotal = total;
    drawFooter("SEL details  f filter  ^v select  <-exit");
}

void openDetails() {
    if (cursor < 0 || cursor >= listTotal) return;
    int slot = listIdx[cursor];
    const Threat &t = threats[slot];
    detailOpen = true;
    detailSlot = slot;
    strlcpy(detailAddr, t.addr, sizeof(detailAddr));
    strlcpy(detailKind, t.kind, sizeof(detailKind));
    detailFirstMs = t.firstMs;
    detailScroll = 0;
    Serial.printf("[Watch] details -> %s %s\n", t.kind, t.addr);
}
void closeDetails() {
    detailOpen = false;
    Serial.println("[Watch] details closed -> list");
}
void cycleFilter() {
    alertFilter = (alertFilter + 1) % 3; // All -> Med+ -> High -> All
    cursor = scroll = 0;
    Serial.printf("[Watch] filter -> %s\n", filterName(alertFilter));
}

// ── Radio phase control ──────────────────────────────────────────────────────
// Each phase owns the radio AND its memory: the WiFi phase runs with the BLE
// stack torn down, the BLE phase with WiFi off. ble_scan_setup() only drops WiFi
// when FORCE_RADIO_TEARDOWN_ON_SWITCH is set, and that is false on this board, so
// both stacks used to be resident together through the BLE phase -- which is how
// the internal heap got down to ~9 KB. Alternating them keeps real headroom in
// both phases; the heap figures in the phase log are there to confirm it.
void startWifiPhase(uint8_t chIdx) {
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wifi_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(wifi_channels[chIdx], WIFI_SECOND_CHAN_NONE);
}
void stopWifiPhase(bool releaseStack) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    if (releaseStack) {
        WiFi.mode(WIFI_MODE_NULL); // frees the WiFi driver buffers for the BLE phase
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}
void startBlePhase() {
    ble_scan_setup(); // BLEDevice::init + getScan (WiFi is already off)
    // NOTE: the second argument is wantDuplicates, NOT deleteCallbacks -- it calls
    // setDuplicateFilter(!wantDuplicates) internally. Passing false here would switch
    // the controller's duplicate filter ON, and a filtered device is reported once and
    // then never again, so the watch would quietly stop listing BLE threats.
    pBLEScan->setScanCallbacks(&bleCb, true);
    pBLEScan->setActiveScan(false);      // passive: receive-only, never transmit
    pBLEScan->setMaxResults(0);          // callback-only, don't buffer results
    pBLEScan->setDuplicateFilter(false); // explicit: keep re-reporting every phase
    pBLEScan->start(0, false);
}
void stopBlePhase() {
    if (pBLEScan) pBLEScan->stop();
    vTaskDelay(20 / portTICK_PERIOD_MS); // let an in-flight onResult() finish
    stopBLEStack();
}

// Last typed character on keyboard boards, 0 if none. (Backspace needs no
// handling here: the board's input handler already turns it into EscPress.)
char typedKey() {
#ifdef HAS_KEYBOARD
    keyStroke k = _getKeyPress();
    if (k.pressed && !k.word.empty()) return k.word[0];
#endif
    return 0;
}

} // namespace

void ambient_watch() {
    Serial.println("[Watch] Ambient Watch starting (passive, time-sliced WiFi<->BLE)");
    cs::runCsClassifySelfTest();

    if (!allocThreats()) {
        Serial.println("[Watch] cannot allocate threat table - aborting");
        displayError("Out of memory", true);
        return;
    }
    threatCount = 0;
    ringHead = ringTail = ringDropped = 0;
    wifiFrames = 0;
    cursor = scroll = 0;
    listTotal = 0;
    detailOpen = false;
    watchSetupSd();
    alertFilter = cs::CONF_MED;
    alertUntil = 0;
    alertKind[0] = 0;
    g_resting = false;
    fullClear = true;

    wifi_mode_t prevMode = WiFi.getMode();

    constexpr uint32_t WIFI_PHASE_MS = 8000;
    constexpr uint32_t BLE_PHASE_MS = 6000;
    constexpr uint32_t REST_PHASE_MS = 3000; // radios idle: cuts power/heat on long watches
    constexpr uint32_t HOP_MS = 350;

    bool blePhase = false;
    uint8_t chIdx = 0;
    startWifiPhase(chIdx);
    uint32_t phaseStart = millis(), lastHop = millis();
    awDraw(blePhase, wifi_channels[chIdx]);

    for (;;) {
        // Backspace raises EscPress: back to the list from details, exit from the list.
        if (check(EscPress)) {
            if (!detailOpen) break;
            closeDetails();
        }
        Event ev;
        int drained = 0;
        while (drained++ < 32 && ringPop(ev)) onEvent(ev);

        uint32_t now = millis();
        // WiFi channel hop within the WiFi phase.
        if (!blePhase && !g_resting && now - lastHop > HOP_MS) {
            lastHop = now;
            chIdx = (chIdx + 1) % N_WIFI_CH;
            esp_wifi_set_channel(wifi_channels[chIdx], WIFI_SECOND_CHAN_NONE);
        }
        // Phase cycle: WIFI -> BLE -> REST -> WIFI. REST idles both radios to cut
        // power/heat on long watches. No fullClear on a switch: per-row diffing
        // repaints only the changed [BLE]/[WIFI]/[REST] header, so the threat list
        // and any active alert stay on screen.
        uint32_t phaseLen = g_resting ? REST_PHASE_MS : (blePhase ? BLE_PHASE_MS : WIFI_PHASE_MS);
        if (now - phaseStart > phaseLen) {
            if (g_resting) { // REST done -> WiFi
                g_resting = false;
                blePhase = false;
                chIdx = 0;
                startWifiPhase(chIdx);
            } else if (blePhase) { // BLE done -> REST (BLE stack torn down, radios idle)
                stopBlePhase();
                blePhase = false;
                g_resting = true;
            } else { // WiFi done -> BLE
                stopWifiPhase(true);
                startBlePhase();
                blePhase = true;
            }
            phaseStart = millis();
            lastHop = millis();
            Serial.printf("[Watch] phase -> %s\n", g_resting ? "REST" : (blePhase ? "BLE" : "WIFI"));
        }

        // Input never blocks: events keep draining and phases keep switching
        // above whichever view is open, so nothing is lost while reading details.
        char key = typedKey();
        if (key == 'F') key = 'f';
        if (key == 'B') key = 'b';
        if (detailOpen) {
            if (key == 'b') closeDetails();
            if (check(PrevPress)) detailScroll--;
            if (check(NextPress)) detailScroll++;
            check(SelPress); // swallow: SEL has no meaning here
        } else {
            if (key == 'f') cycleFilter();
            if (check(SelPress)) openDetails();
            if (check(PrevPress) && cursor > 0) cursor--;
            if (check(NextPress)) cursor++;
        }

        awDraw(blePhase, wifi_channels[chIdx]);
        delay(15);
    }

    if (blePhase) stopBlePhase();
    else if (!g_resting) stopWifiPhase(false); // during REST both radios are already idle
    freeThreats();
    WiFi.mode(prevMode);
    Serial.printf("[Watch] stopped. threats=%u wifiFrames=%lu dropped=%lu\n",
                  (unsigned)threatCount, (unsigned long)wifiFrames, (unsigned long)ringDropped);
}
