#include "wifi_camera_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "oui_db.h"
#include <WiFi.h>
#include <ctype.h>
#include <esp_wifi.h>
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive (receive-only) WiFi camera detector. Same capture substrate as
// passive_recon.cpp: STA mode (never AP, so we never beacon) + promiscuous
// management-frame capture, channel-hopping. The rx callback classifies each
// beacon/probe against the shared camera OUI table (oui_db) and a set of
// camera-name SSID patterns, and pushes only candidate hits to a SPSC ring; the
// main loop dedups them by MAC into an RSSI-sorted table, mirrors to serial, and
// logs raw sightings to SD. Generic Wi-Fi module OUIs (ESP/Realtek) are flagged
// low-confidence so a plain ESP32 with a camera-ish name isn't a false positive.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

const uint8_t cam_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
constexpr size_t N_CHANNELS = sizeof(cam_channels);

enum Conf : uint8_t { CONF_LOW = 0, CONF_MED = 1, CONF_HIGH = 2 };
constexpr uint8_t VIA_OUI = 0x01;
constexpr uint8_t VIA_SSID = 0x02;

const char *confName(uint8_t c) { return c == CONF_HIGH ? "HIGH" : c == CONF_MED ? "MED" : "LOW"; }

// Camera-name SSID substrings (case-insensitive) are sourced from
// bruceConfig.camSsidPatterns (editable in bruce.conf, seeded with sane defaults).
// Deliberately broad; a bare generic-OUI match on one of these only yields LOW
// confidence.

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

bool ssidMatchesCamera(const char *ssid) {
    if (!ssid || !ssid[0]) return false;
    for (const auto &pat : bruceConfig.camSsidPatterns)
        if (ciContains(ssid, pat.c_str())) return true;
    return false;
}

// Decide whether (mac, ssid) looks like a camera. Fills conf/vendor/klass/via.
// Trigger = a CAM-class OUI, or a camera-name SSID. Generic-module OUIs downgrade
// an SSID-only match to LOW confidence.
bool classifyCam(
    const uint8_t *mac, const char *ssid, uint8_t &conf, const char *&vendor, uint8_t &klass,
    uint8_t &via
) {
    const OuiEntry *o = lookupOui(mac);
    bool ouiCam = o && o->klass == OUI_CAM;
    bool ouiGen = o && o->klass == OUI_GENERIC;
    bool ouiIot = o && o->klass == OUI_IOT;
    bool ssidHit = ssidMatchesCamera(ssid);

    if (!ouiCam && !ssidHit) return false; // not a camera candidate

    vendor = o ? o->vendor : (ssidHit ? "by-SSID" : "?");
    klass = o ? o->klass : OUI_NONE;
    via = (uint8_t)((o ? VIA_OUI : 0) | (ssidHit ? VIA_SSID : 0));

    if (ouiCam) conf = CONF_HIGH;               // known camera vendor
    else if (ssidHit && ouiIot) conf = CONF_HIGH; // IoT vendor + camera name
    else if (ssidHit && ouiGen) conf = CONF_LOW;  // generic module + camera-ish name
    else conf = CONF_MED;                        // camera-ish name, unknown vendor
    return true;
}

// ── Capture event (callback -> ring) ─────────────────────────────────────────
struct CamEvent {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint8_t ch;
    uint8_t conf;
    uint8_t klass;
    uint8_t via;
    const char *vendor; // points to flash string in oui_db or a static literal
};

constexpr size_t RING_SZ = 64;
CamEvent ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;
volatile uint32_t cbFrames = 0;
volatile uint32_t cbHits = 0;

void ringPush(const CamEvent &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(CamEvent &e) {
    if (ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

// Extract SSID (tag 0) from tagged parameters starting at `off`.
void extractSsid(const uint8_t *p, int len, int off, char *out) {
    out[0] = 0;
    int o = off;
    while (o + 2 <= len) {
        uint8_t tag = p[o];
        uint8_t tl = p[o + 1];
        if (o + 2 + tl > len) break;
        if (tag == 0) {
            int n = tl > 32 ? 32 : tl;
            int j = 0;
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

void cam_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 0) return; // management only
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    // Candidate MAC + SSID by frame type:
    //   probe req (0x04):  device = src (p+10), ssid = requested SSID
    //   beacon/probe-resp: device = bssid (p+16), ssid = AP name
    const uint8_t *mac;
    char ssid[33];
    if (subtype == 0x04) {
        mac = p + 10;
        extractSsid(p, len, 24, ssid);
    } else if (subtype == 0x08 || subtype == 0x05) {
        mac = p + 16;
        extractSsid(p, len, 36, ssid);
    } else {
        return; // ignore other mgmt frames
    }
    cbFrames = cbFrames + 1;

    uint8_t conf, klass, via;
    const char *vendor;
    if (!classifyCam(mac, ssid, conf, vendor, klass, via)) return;

    CamEvent e = {};
    memcpy(e.mac, mac, 6);
    strlcpy(e.ssid, ssid, sizeof(e.ssid));
    e.rssi = pkt->rx_ctrl.rssi;
    e.ch = pkt->rx_ctrl.channel;
    e.conf = conf;
    e.klass = klass;
    e.via = via;
    e.vendor = vendor;
    cbHits = cbHits + 1;
    ringPush(e);
}

// ── Table ────────────────────────────────────────────────────────────────────
struct CamEnt {
    uint8_t mac[6];
    char vendor[20];
    char ssid[33];
    uint8_t klass;
    int8_t rssi;     // last
    int8_t bestRssi; // strongest (closest)
    uint8_t ch;
    uint8_t conf;
    uint8_t via;
    uint16_t count;
    uint32_t firstMs;
    uint32_t lastMs;
};
constexpr size_t CAM_MAX = 128;
std::vector<CamEnt> cams;

enum SortMode : uint8_t { SORT_RSSI = 0, SORT_LASTSEEN = 1, SORT_COUNT = 2 };
SortMode sortMode = SORT_RSSI;
const char *sortName(uint8_t m) {
    return m == SORT_RSSI ? "signal" : m == SORT_LASTSEEN ? "last-seen" : "count";
}
int scroll = 0;
int cursor = 0;        // selected row (index into the sorted display order)
bool detailView = false; // showing the per-camera detail page for `cursor`

// Channel hop state.
size_t chIdx = 0;
bool chLocked = false;
uint32_t lastHopMs = 0;
constexpr uint32_t HOP_MS = 300;

// ── SD logging ───────────────────────────────────────────────────────────────
bool camSd = false;
const char *DET_DIR = "/BruceDetector";
const char *CAM_CSV = "/BruceDetector/wifi_cams.csv";

String macStr(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
}
String viaStr(uint8_t via) {
    String s;
    if (via & VIA_OUI) s += "OUI";
    if (via & VIA_SSID) s += s.length() ? "+SSID" : "SSID";
    return s.length() ? s : String("-");
}
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

void logSighting(const CamEvent &e) {
    if (!camSd) return;
    File f = SD.open(CAM_CSV, FILE_APPEND);
    if (!f) return;
    f.println(
        String(millis()) + "," + nowClk() + "," + macStr(e.mac) + "," + e.vendor + "," +
        ouiClassName(e.klass) + ",\"" + String(e.ssid) + "\"," + String(e.rssi) + "," + String(e.ch) +
        "," + confName(e.conf) + "," + viaStr(e.via)
    );
    f.close();
}

// ── Model update (main loop) ─────────────────────────────────────────────────
bool sameMac(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

void onCam(const CamEvent &e) {
    for (auto &c : cams) {
        if (sameMac(c.mac, e.mac)) {
            c.rssi = e.rssi;
            if (e.rssi > c.bestRssi) c.bestRssi = e.rssi;
            c.ch = e.ch;
            c.lastMs = millis();
            if (c.count < 0xFFFF) c.count++;
            if (e.conf > c.conf) c.conf = e.conf;
            c.via |= e.via;
            if (c.ssid[0] == 0 && e.ssid[0]) strlcpy(c.ssid, e.ssid, sizeof(c.ssid));
            if (e.klass == OUI_CAM || e.klass == OUI_IOT) {
                c.klass = e.klass;
                strlcpy(c.vendor, e.vendor, sizeof(c.vendor));
            }
            logSighting(e);
            return;
        }
    }
    if (cams.size() >= CAM_MAX) { // evict least-recently-seen
        size_t oldest = 0;
        for (size_t i = 1; i < cams.size(); i++)
            if (cams[i].lastMs < cams[oldest].lastMs) oldest = i;
        cams.erase(cams.begin() + oldest);
    }
    CamEnt c = {};
    memcpy(c.mac, e.mac, 6);
    strlcpy(c.vendor, e.vendor, sizeof(c.vendor));
    strlcpy(c.ssid, e.ssid, sizeof(c.ssid));
    c.klass = e.klass;
    c.rssi = c.bestRssi = e.rssi;
    c.ch = e.ch;
    c.conf = e.conf;
    c.via = e.via;
    c.count = 1;
    c.firstMs = c.lastMs = millis();
    cams.push_back(c);
    logSighting(e);
    Serial.printf(
        "[CamDetect] HIT %s vendor=%s ssid=\"%s\" rssi=%d ch=%u conf=%s via=%s\n",
        macStr(e.mac).c_str(), e.vendor, e.ssid, e.rssi, e.ch, confName(e.conf), viaStr(e.via).c_str()
    );
}

// ── Rendering (per-row diffed, no periodic full clears -> no flicker) ─────────
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
    for (auto &e : cams)
        if (e.conf == CONF_HIGH) c++;
    return c;
}

void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(
        l0, sizeof(l0), "WiFi Cam  CH%02u%s  drop:%lu", cam_channels[chIdx], chLocked ? "[L]" : "   ",
        (unsigned long)ringDropped
    );
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    int hi = highConfCount();
    char l1[64];
    snprintf(l1, sizeof(l1), "cams:%u  high:%d  sort:%s", (unsigned)cams.size(), hi, sortName(sortMode));
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(hi > 0 ? TFT_RED : (cams.empty() ? TFT_GREEN : TFT_YELLOW), TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}

void drawFooter() {
    String hint = detailView ? "<-/SEL back  ^v scroll" : "SEL details  ^v select  s sort  l lock  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

// Short "N units ago" / span formatter for the detail page.
String fmtSpan(uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60) return String(s) + "s";
    if (s < 3600) return String(s / 60) + "m" + String(s % 60) + "s";
    return String(s / 3600) + "h" + String((s % 3600) / 60) + "m";
}

// Build the sorted display order (shared by table + detail so `cursor` maps to
// the same camera in both).
void buildCamOrder(std::vector<int> &idx) {
    idx.resize(cams.size());
    for (size_t i = 0; i < cams.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) {
        const CamEnt &A = cams[a], &B = cams[b];
        if (sortMode == SORT_RSSI) return A.bestRssi > B.bestRssi;
        if (sortMode == SORT_LASTSEEN) return A.lastMs > B.lastMs;
        return A.count > B.count;
    });
}

void drawBody() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    std::vector<int> idx;
    buildCamOrder(idx);

    int total = (int)idx.size();
    if (cursor >= total) cursor = total ? total - 1 : 0;
    if (cursor < 0) cursor = 0;
    if (cursor < scroll) scroll = cursor;
    if (cursor >= scroll + rows) scroll = cursor - rows + 1;
    int maxScroll = total - rows;
    if (maxScroll < 0) maxScroll = 0;
    if (scroll > maxScroll) scroll = maxScroll;
    if (scroll < 0) scroll = 0;

    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int li = scroll + slot;
        if (li >= total) {
            if (total == 0 && slot == 0)
                drawRow(slot, y, "  (listening for cameras...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const CamEnt &c = cams[idx[li]];
        char cflag = c.conf == CONF_HIGH ? 'H' : c.conf == CONF_MED ? 'M' : 'L';
        String ven = String(c.vendor);
        if (ven.length() > 9) ven = ven.substring(0, 9);
        String name = c.ssid[0] ? String(c.ssid) : String("<hidden>");
        if (name.length() > 11) name = name.substring(0, 11);
        String macTail = macStr(c.mac).substring(9); // last 3 octets
        String line = String(li == cursor ? '>' : ' ') + String(cflag) + " " + ven + " " + name +
                      " c" + String(c.ch) + " " + String(c.rssi) + " x" + String(c.count) + " " + macTail;
        uint16_t fg = li == cursor ? TFT_CYAN
                      : c.conf == CONF_HIGH ? TFT_RED
                      : c.conf == CONF_MED  ? TFT_YELLOW
                                            : TFT_DARKGREY;
        drawRow(slot, y, line, fg);
    }
}

// Per-camera detail page: full MAC, guessed vendor from the OUI table, and a
// plain-language explanation of *why* this device was flagged (which signal(s)
// fired and how they set the confidence).
void drawDetail() {
    std::vector<int> idx;
    buildCamOrder(idx);
    if (idx.empty()) {
        drawRow(0, CHROME_H, "  (no camera selected)", TFT_DARKGREY);
        for (int s = 1; s < MAX_ROWS; s++) drawRow(s, CHROME_H + s * ROW_H, "", TFT_WHITE);
        return;
    }
    if (cursor >= (int)idx.size()) cursor = idx.size() - 1;
    if (cursor < 0) cursor = 0;
    const CamEnt &c = cams[idx[cursor]];

    char ouiPfx[9];
    snprintf(ouiPfx, sizeof(ouiPfx), "%02X:%02X:%02X", c.mac[0], c.mac[1], c.mac[2]);

    String lines[MAX_ROWS];
    uint16_t fgs[MAX_ROWS];
    for (int i = 0; i < MAX_ROWS; i++) { lines[i] = ""; fgs[i] = TFT_WHITE; }
    int n = 0;
    uint16_t confFg = c.conf == CONF_HIGH ? TFT_RED : c.conf == CONF_MED ? TFT_YELLOW : TFT_DARKGREY;

    lines[n] = String("MAC: ") + macStr(c.mac); fgs[n++] = TFT_WHITE;
    lines[n] = String("Vendor: ") + c.vendor; fgs[n++] = TFT_CYAN;
    lines[n] = String("OUI ") + ouiPfx + "  class: " + ouiClassName(c.klass); fgs[n++] = TFT_WHITE;
    lines[n] = String("SSID: ") + (c.ssid[0] ? String(c.ssid) : String("<hidden>")); fgs[n++] = TFT_WHITE;
    lines[n] = String("Channel: ") + c.ch + "   RSSI: " + c.rssi + " (best " + c.bestRssi + ")";
    fgs[n++] = TFT_WHITE;
    lines[n] = String("Seen x") + c.count + "  first " + fmtSpan(millis() - c.firstMs) + " ago";
    fgs[n++] = TFT_WHITE;
    lines[n] = String("Last seen ") + fmtSpan(millis() - c.lastMs) + " ago"; fgs[n++] = TFT_WHITE;
    lines[n] = String("Confidence: ") + confName(c.conf); fgs[n++] = confFg;
    lines[n] = ""; fgs[n++] = TFT_WHITE;
    lines[n] = "Why flagged:"; fgs[n++] = bruceConfig.priColor;
    if (c.via & VIA_OUI) {
        lines[n] = String("- OUI ") + ouiPfx + " = " + c.vendor;
        fgs[n++] = TFT_WHITE;
        lines[n] = String("  (") +
                   (c.klass == OUI_CAM ? "known camera vendor)"
                    : c.klass == OUI_IOT ? "IoT/surveil vendor)"
                    : c.klass == OUI_GENERIC ? "generic Wi-Fi module)"
                                             : "vendor prefix)");
        fgs[n++] = TFT_WHITE;
    }
    if (c.via & VIA_SSID) {
        lines[n] = "- SSID matches a camera name"; fgs[n++] = TFT_WHITE;
        lines[n] = "  pattern (IPC-/Wyze/Reolink..)"; fgs[n++] = TFT_WHITE;
    }
    if (c.conf == CONF_LOW) {
        lines[n] = "Low: generic module + name only"; fgs[n++] = TFT_DARKGREY;
    }

    for (int slot = 0; slot < MAX_ROWS; slot++)
        drawRow(slot, CHROME_H + slot * ROW_H, lines[slot], fgs[slot]);
}

void camDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome();
    if (detailView) drawDetail();
    else drawBody();
    drawFooter();
}

void hopChannel() {
    esp_wifi_set_promiscuous(false);
    chIdx = (chIdx + 1) % N_CHANNELS;
    esp_wifi_set_channel(cam_channels[chIdx], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

// Dump the current table to serial (headless verification: type any line + Enter).
void dumpTableSerial() {
    Serial.printf("[CamDetect] table (%u devices):\n", (unsigned)cams.size());
    for (auto &c : cams) {
        Serial.printf(
            "  %s  %-9s  %-16s  ch%u  rssi=%d(best%d)  x%u  conf=%s  via=%s\n", macStr(c.mac).c_str(),
            c.vendor, c.ssid[0] ? c.ssid : "<hidden>", c.ch, c.rssi, c.bestRssi, c.count,
            confName(c.conf), viaStr(c.via).c_str()
        );
    }
}

} // namespace

void wifi_camera_detector() {
    Serial.println("[CamDetect] passive WiFi camera detector starting (RX-only)");
    cams.clear();
    ringHead = ringTail = ringDropped = 0;
    cbFrames = cbHits = 0;
    sortMode = SORT_RSSI;
    scroll = 0;
    cursor = 0;
    detailView = false;
    chIdx = 0;
    chLocked = false;
    fullClear = true;

    // SD logging (best-effort). Write CSV header on first create.
    camSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(DET_DIR)) SD.mkdir(DET_DIR);
        camSd = true;
        if (!SD.exists(CAM_CSV)) {
            File f = SD.open(CAM_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,clock,mac,vendor,klass,ssid,rssi,channel,confidence,via");
                f.close();
            }
        }
        Serial.printf("[CamDetect] logging -> %s\n", CAM_CSV);
    } else {
        Serial.println("[CamDetect] no SD card - logging disabled");
    }

    // Promiscuous RX in STA mode (STA never beacons; idle unconnected STA is silent).
    wifi_mode_t prevMode = WiFi.getMode();
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(cam_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(cam_channels[chIdx], WIFI_SECOND_CHAN_NONE);

    camDraw();
    lastHopMs = millis();

    while (true) {
        CamEvent e;
        int drained = 0;
        while (drained++ < 64 && ringPop(e)) onCam(e);

        if (!chLocked && millis() - lastHopMs > HOP_MS) {
            lastHopMs = millis();
            hopChannel();
        }

        // ESC: in the detail page, go back to the list; in the list, exit.
        if (check(EscPress)) {
            if (detailView) {
                detailView = false;
                fullClear = true;
            } else break;
        }
        if (check(SelPress)) {
            // Open the detail page for the selected row, or close it if open.
            if (detailView) detailView = false;
            else if (!cams.empty()) detailView = true;
            fullClear = true;
        }
        if (check(PrevPress)) {
            if (detailView) { /* single camera view */ }
            else if (cursor > 0) cursor--;
        }
        if (check(NextPress)) {
            if (!detailView) cursor++;
        }
        char ch = checkLetterShortcutPress();
        if (ch == 's' || ch == 'S') {
            sortMode = (SortMode)((sortMode + 1) % 3);
            cursor = 0;
            scroll = 0;
        }
        if (ch == 'l' || ch == 'L') chLocked = !chLocked;

        // Headless trigger: any serial line dumps the current table.
        if (Serial.available()) {
            while (Serial.available()) Serial.read();
            dumpTableSerial();
        }

        camDraw();
        delay(15);
    }

    // Teardown: stop promiscuous, restore previous WiFi mode.
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevMode);
    Serial.printf(
        "[CamDetect] stopped. cams=%u high=%d frames=%lu hits=%lu dropped=%lu\n",
        (unsigned)cams.size(), highConfCount(), (unsigned long)cbFrames, (unsigned long)cbHits,
        (unsigned long)ringDropped
    );
}
