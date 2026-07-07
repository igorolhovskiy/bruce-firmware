#include "drone_remoteid.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "modules/ble/ble_common.h"
#include <WiFi.h>
#include <ctype.h>
#include <esp_wifi.h>
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive Open Drone ID (ASTM F3411 "Remote ID") detector. Fully receive-only.
//
// One shared message parser decodes the ODID Basic ID / Location / System /
// Operator-ID messages (and Message Packs). It is fed from two transports,
// switched by mode (W/B) so the shared 2.4 GHz radio is never asked to do
// promiscuous WiFi and a NimBLE scan at once:
//   - WiFi: promiscuous management-frame capture; each frame is scanned for the
//     ASTM vendor signature FA-0B-BC-0D (covers the Beacon vendor-IE and the
//     NAN/action-frame carriers), then the following message pack is parsed.
//   - BLE:  passive scan; Service Data (AD 0x16) UUID 0xFFFA, app code 0x0D.
//
// Drones are de-duplicated by transmitter address into a table (Basic ID fills
// the UAS id/type, Location fills drone lat/lon/alt/speed, System fills the
// OPERATOR location). A detailView view shows drone-vs-operator coordinates. Every
// sighting is mirrored to serial and logged to SD. A typed serial hex line is
// parsed as a synthetic message for headless byte-for-byte parser validation.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

const uint8_t rid_channels[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
constexpr size_t N_CHANNELS = sizeof(rid_channels);

enum SrcType : uint8_t { SRC_WIFI = 1, SRC_BLE = 2, SRC_TEST = 3 };
const char *srcTag(uint8_t s) { return s == SRC_WIFI ? "W" : s == SRC_BLE ? "B" : "T"; }

const char *uaTypeName(uint8_t t) {
    switch (t) {
    case 0: return "None";
    case 1: return "Aeroplane";
    case 2: return "Multirotor";
    case 3: return "Gyroplane";
    case 4: return "HybridLift";
    case 5: return "Ornithopter";
    case 6: return "Glider";
    case 7: return "Kite";
    case 8: return "FreeBalloon";
    case 9: return "Captive";
    case 10: return "Airship";
    case 11: return "Parachute";
    case 12: return "Rocket";
    case 13: return "TetheredBal";
    case 14: return "GroundObst";
    default: return "?";
    }
}

// ── Raw capture event (transport callback -> ring) ───────────────────────────
struct OdidEvent {
    char addr[18];
    int8_t rssi;
    uint8_t ch;      // 0 for BLE/test
    uint8_t srcType; // SrcType
    uint8_t len;
    uint8_t data[232]; // ODID messages (counter byte already stripped)
};

constexpr size_t RING_SZ = 6;
OdidEvent ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;
volatile uint32_t cbHits = 0;

void ringPush(const OdidEvent &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(OdidEvent &e) {
    if (ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

// ── Decoded drone model ──────────────────────────────────────────────────────
struct DroneEnt {
    char addr[18];
    char id[21]; // UAS ID / serial
    char opId[21];
    uint8_t uaType;
    double droneLat, droneLon;
    float droneAlt; // geodetic, m
    float speed;    // m/s
    uint16_t track; // deg
    double opLat, opLon;
    float opAlt;
    bool haveId, haveLoc, haveOp;
    int8_t rssi, bestRssi;
    uint8_t srcType;
    uint16_t count;
    uint32_t firstMs, lastMs;
};
constexpr size_t DRONE_MAX = 48;
std::vector<DroneEnt> drones;
int scroll = 0;
int cursor = 0;   // selected row (into display order)
bool detailView = false;

// ── ODID message parsing (shared, integer/float math only) ───────────────────
int32_t le32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}
uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

void copyAscii(char *dst, size_t dstsz, const uint8_t *src, size_t n) {
    size_t j = 0;
    for (size_t i = 0; i < n && j + 1 < dstsz; i++) {
        uint8_t c = src[i];
        if (c >= 0x20 && c < 0x7f) dst[j++] = (char)c;
        else if (c == 0) break;
    }
    dst[j] = 0;
}

// Decode a single 25-byte ODID message into `d`. Returns true if it changed d.
bool decodeMsg(const uint8_t *m, DroneEnt &d) {
    uint8_t type = m[0] >> 4;
    if (type == 0x0) { // Basic ID
        d.uaType = m[1] & 0x0F;
        copyAscii(d.id, sizeof(d.id), m + 2, 20);
        d.haveId = true;
        return true;
    }
    if (type == 0x1) { // Location / Vector
        uint8_t ewBit = (m[1] >> 1) & 0x01;
        uint8_t speedMult = m[1] & 0x01;
        uint16_t track = m[2] + (ewBit ? 180 : 0);
        d.track = track % 360;
        uint8_t sraw = m[3];
        d.speed = speedMult ? (sraw * 0.75f + 63.75f) : (sraw * 0.25f);
        d.droneLat = le32(m + 5) / 1e7;
        d.droneLon = le32(m + 9) / 1e7;
        d.droneAlt = le16(m + 15) * 0.5f - 1000.0f; // geodetic altitude
        d.haveLoc = true;
        return true;
    }
    if (type == 0x4) { // System (operator location)
        d.opLat = le32(m + 2) / 1e7;
        d.opLon = le32(m + 6) / 1e7;
        d.opAlt = le16(m + 18) * 0.5f - 1000.0f;
        d.haveOp = true;
        return true;
    }
    if (type == 0x5) { // Operator ID
        copyAscii(d.opId, sizeof(d.opId), m + 2, 20);
        return true;
    }
    return false; // Auth / Self-ID / reserved: ignored
}

// Parse a buffer of ODID messages (a Message Pack, or back-to-back 25-byte msgs)
// into `d`. Returns number of messages decoded.
int parseOdid(const uint8_t *buf, int n, DroneEnt &d) {
    if (n < 25) return 0;
    int decoded = 0;
    if ((buf[0] >> 4) == 0xF) { // Message Pack
        uint8_t msgSize = buf[1];
        uint8_t cnt = buf[2];
        if (msgSize != 25) msgSize = 25;
        const uint8_t *base = buf + 3;
        int avail = n - 3;
        for (int i = 0; i < cnt && (i + 1) * 25 <= avail; i++) {
            if (decodeMsg(base + i * 25, d)) decoded++;
        }
    } else {
        for (int off = 0; off + 25 <= n; off += 25) {
            if (decodeMsg(buf + off, d)) decoded++;
        }
    }
    return decoded;
}

// ── WiFi promiscuous capture ─────────────────────────────────────────────────
volatile uint8_t curCh = 1;

void wifi_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;
    if (((p[0] >> 2) & 0x03) != 0) return; // management only

    // Search for the ASTM ODID vendor signature FA-0B-BC-0D anywhere in the body.
    // Covers the Beacon vendor-IE and NAN/action-frame carriers uniformly.
    int sigAt = -1;
    for (int i = 24; i + 4 <= len; i++) {
        if (p[i] == 0xFA && p[i + 1] == 0x0B && p[i + 2] == 0xBC && p[i + 3] == 0x0D) {
            sigAt = i;
            break;
        }
    }
    if (sigAt < 0) return;

    int msgStart = sigAt + 5; // skip OUI(3)+vendorType(1)+msgCounter(1)
    int avail = len - msgStart;
    if (avail < 25) return;

    OdidEvent e = {};
    snprintf(e.addr, sizeof(e.addr), "%02X:%02X:%02X:%02X:%02X:%02X", p[10], p[11], p[12], p[13], p[14],
             p[15]); // source address
    e.rssi = pkt->rx_ctrl.rssi;
    e.ch = pkt->rx_ctrl.channel;
    e.srcType = SRC_WIFI;
    e.len = avail > (int)sizeof(e.data) ? (uint8_t)sizeof(e.data) : (uint8_t)avail;
    memcpy(e.data, p + msgStart, e.len);
    cbHits = cbHits + 1;
    ringPush(e);
}

// ── BLE passive capture ──────────────────────────────────────────────────────
class DroneBleCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *dev) override {
        const std::vector<uint8_t> &pl = dev->getPayload();
        const uint8_t *p = pl.data();
        size_t n = pl.size();
        size_t i = 0;
        while (i + 1 < n) {
            uint8_t len = p[i];
            if (len == 0 || i + 1 + len > n) break;
            uint8_t t = p[i + 1];
            const uint8_t *d = &p[i + 2];
            uint8_t dl = len - 1;
            // Service Data - 16-bit UUID 0xFFFA (ASTM), app code 0x0D.
            if (t == 0x16 && dl >= 4 && d[0] == 0xFA && d[1] == 0xFF && d[2] == 0x0D) {
                const uint8_t *msg = d + 4; // skip uuid(2)+appcode(1)+counter(1)
                int avail = (int)dl - 4;
                if (avail >= 25) {
                    OdidEvent e = {};
                    strlcpy(e.addr, dev->getAddress().toString().c_str(), sizeof(e.addr));
                    e.rssi = dev->getRSSI();
                    e.ch = 0;
                    e.srcType = SRC_BLE;
                    e.len = avail > (int)sizeof(e.data) ? (uint8_t)sizeof(e.data) : (uint8_t)avail;
                    memcpy(e.data, msg, e.len);
                    cbHits = cbHits + 1;
                    ringPush(e);
                }
            }
            i += 1 + len;
        }
    }
};

// ── SD logging ───────────────────────────────────────────────────────────────
bool droneSd = false;
const char *DET_DIR = "/BruceDetector";
const char *DRONE_CSV = "/BruceDetector/drones.csv";

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

void logDrone(const DroneEnt &d) {
    if (!droneSd) return;
    File f = SD.open(DRONE_CSV, FILE_APPEND);
    if (!f) return;
    char line[220];
    snprintf(
        line, sizeof(line),
        "%lu,%s,%s,%s,\"%s\",%s,%.7f,%.7f,%.1f,%.1f,%u,%.7f,%.7f,%.1f,%d",
        (unsigned long)millis(), nowClk().c_str(), srcTag(d.srcType), d.addr, d.id,
        uaTypeName(d.uaType), d.droneLat, d.droneLon, d.droneAlt, d.speed, d.track, d.opLat, d.opLon,
        d.opAlt, d.rssi
    );
    f.println(line);
    f.close();
}

// ── Model update (main loop) ─────────────────────────────────────────────────
void onEvent(const OdidEvent &e) {
    DroneEnt *cur = nullptr;
    for (auto &d : drones)
        if (strcmp(d.addr, e.addr) == 0) {
            cur = &d;
            break;
        }
    bool isNew = false;
    if (!cur) {
        if (drones.size() >= DRONE_MAX) {
            size_t oldest = 0;
            for (size_t i = 1; i < drones.size(); i++)
                if (drones[i].lastMs < drones[oldest].lastMs) oldest = i;
            drones.erase(drones.begin() + oldest);
        }
        DroneEnt d = {};
        strlcpy(d.addr, e.addr, sizeof(d.addr));
        d.rssi = d.bestRssi = e.rssi;
        d.srcType = e.srcType;
        d.count = 0;
        d.firstMs = millis();
        drones.push_back(d);
        cur = &drones.back();
        isNew = true;
    }
    int decoded = parseOdid(e.data, e.len, *cur);
    cur->rssi = e.rssi;
    if (e.rssi > cur->bestRssi) cur->bestRssi = e.rssi;
    cur->srcType = e.srcType;
    cur->lastMs = millis();
    if (cur->count < 0xFFFF) cur->count++;
    logDrone(*cur);
    if (isNew || decoded) {
        Serial.printf(
            "[DroneRID] %s src=%s id=\"%s\" type=%s rssi=%d loc=%s op=%s\n", cur->addr,
            srcTag(cur->srcType), cur->id, uaTypeName(cur->uaType), cur->rssi,
            cur->haveLoc ? "Y" : "-", cur->haveOp ? "Y" : "-"
        );
        if (cur->haveLoc)
            Serial.printf(
                "           drone lat=%.6f lon=%.6f alt=%.1fm spd=%.1f trk=%u\n", cur->droneLat,
                cur->droneLon, cur->droneAlt, cur->speed, cur->track
            );
        if (cur->haveOp)
            Serial.printf(
                "           operator lat=%.6f lon=%.6f alt=%.1fm\n", cur->opLat, cur->opLon, cur->opAlt
            );
    }
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

enum Mode : uint8_t { MODE_WIFI = 0, MODE_BLE = 1 };
Mode mode = MODE_WIFI;

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

void buildOrder(std::vector<int> &idx) {
    idx.resize(drones.size());
    for (size_t i = 0; i < drones.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) { return drones[a].bestRssi > drones[b].bestRssi; });
}

void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    if (mode == MODE_WIFI)
        snprintf(l0, sizeof(l0), "Drone RID  WiFi CH%u  drop:%lu", (unsigned)curCh,
                 (unsigned long)ringDropped);
    else snprintf(l0, sizeof(l0), "Drone RID  BLE  drop:%lu", (unsigned long)ringDropped);
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    char l1[64];
    snprintf(l1, sizeof(l1), "drones:%u  hits:%lu", (unsigned)drones.size(), (unsigned long)cbHits);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(drones.empty() ? TFT_GREEN : TFT_RED, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}

void drawFooter() {
    String hint = detailView ? "<- back" : "SEL detailView  ^v sel  m mode  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

void drawTable() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    std::vector<int> idx;
    buildOrder(idx);
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
                drawRow(slot, y, "  (listening for drones...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const DroneEnt &d = drones[idx[li]];
        String id = d.haveId && d.id[0] ? String(d.id) : String(d.addr).substring(9);
        if (id.length() > 14) id = id.substring(0, 14);
        String flags = String(d.haveLoc ? "L" : "-") + (d.haveOp ? "O" : "-");
        String line = String(li == cursor ? '>' : ' ') + String(srcTag(d.srcType)) + " " + id + " " +
                      String(uaTypeName(d.uaType)).substring(0, 6) + " " + flags + " " + String(d.rssi) +
                      " x" + String(d.count);
        uint16_t fg = li == cursor ? TFT_CYAN : (d.haveOp ? TFT_RED : TFT_WHITE);
        drawRow(slot, y, line, fg);
    }
}

void drawDetail() {
    std::vector<int> idx;
    buildOrder(idx);
    if (idx.empty()) {
        drawRow(0, CHROME_H, "  (no drone selected)", TFT_DARKGREY);
        for (int s = 1; s < MAX_ROWS; s++) drawRow(s, CHROME_H + s * ROW_H, "", TFT_WHITE);
        return;
    }
    if (cursor >= (int)idx.size()) cursor = idx.size() - 1;
    const DroneEnt &d = drones[idx[cursor]];
    String lines[12];
    int n = 0;
    lines[n++] = String("addr: ") + d.addr + " (" + srcTag(d.srcType) + ")";
    lines[n++] = String("UAS id: ") + (d.id[0] ? d.id : "-");
    lines[n++] = String("type: ") + uaTypeName(d.uaType);
    lines[n++] = String("op id: ") + (d.opId[0] ? d.opId : "-");
    lines[n++] = "";
    if (d.haveLoc) {
        char b[40];
        snprintf(b, sizeof(b), "drone: %.6f, %.6f", d.droneLat, d.droneLon);
        lines[n++] = b;
        snprintf(b, sizeof(b), "  alt %.1fm  spd %.1fm/s  trk %u", d.droneAlt, d.speed, d.track);
        lines[n++] = b;
    } else lines[n++] = "drone: (no location yet)";
    if (d.haveOp) {
        char b[40];
        snprintf(b, sizeof(b), "OPERATOR: %.6f, %.6f", d.opLat, d.opLon);
        lines[n++] = b;
        snprintf(b, sizeof(b), "  alt %.1fm", d.opAlt);
        lines[n++] = b;
    } else lines[n++] = "operator: (not broadcast)";
    lines[n++] = String("rssi ") + d.rssi + " (best " + d.bestRssi + ")  x" + d.count;

    for (int slot = 0; slot < MAX_ROWS; slot++) {
        int y = CHROME_H + slot * ROW_H;
        if (slot < n) {
            uint16_t fg = lines[slot].startsWith("OPERATOR") ? TFT_RED
                          : lines[slot].startsWith("drone")   ? TFT_CYAN
                                                              : TFT_WHITE;
            drawRow(slot, y, lines[slot], fg);
        } else drawRow(slot, y, "", TFT_WHITE);
    }
}

void droneDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome();
    if (detailView) drawDetail();
    else drawTable();
    drawFooter();
}

// ── Transport setup / teardown ───────────────────────────────────────────────
wifi_mode_t prevWifiMode;
size_t chIdx = 0;
uint32_t lastHopMs = 0;
constexpr uint32_t HOP_MS = 250;

void startWifi() {
    prevWifiMode = WiFi.getMode();
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wifi_cb);
    esp_wifi_set_promiscuous(true);
    chIdx = 0;
    curCh = rid_channels[chIdx];
    esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
    lastHopMs = millis();
}
void stopWifi() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevWifiMode);
}
void startBle() {
    ble_scan_setup(); // WiFi teardown + BLEDevice::init
    pBLEScan->setScanCallbacks(new DroneBleCallbacks(), true);
    pBLEScan->setActiveScan(false);
    pBLEScan->setMaxResults(0);
    pBLEScan->start(0, false);
}
void stopBle() {
    pBLEScan->stop();
    stopBLEStack();
}

void hopChannel() {
    esp_wifi_set_promiscuous(false);
    chIdx = (chIdx + 1) % N_CHANNELS;
    curCh = rid_channels[chIdx];
    esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

// Parse a serial-provided hex line as a synthetic ODID message (headless test).
void feedSerialHex(const String &lineIn) {
    String line;
    for (size_t i = 0; i < lineIn.length(); i++) {
        char c = lineIn[i];
        if (isxdigit((unsigned char)c)) line += c;
    }
    if (line.length() < 50) { // < 25 bytes
        Serial.println("[DroneRID] serial: send >=25 bytes of ODID hex to test the parser");
        return;
    }
    OdidEvent e = {};
    strlcpy(e.addr, "TEST-SERIAL", sizeof(e.addr));
    e.rssi = -1;
    e.srcType = SRC_TEST;
    int nb = line.length() / 2;
    if (nb > (int)sizeof(e.data)) nb = sizeof(e.data);
    for (int i = 0; i < nb; i++) {
        e.data[i] = (uint8_t)strtol(line.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    e.len = nb;
    Serial.printf("[DroneRID] serial test feed: %d bytes\n", nb);
    ringPush(e);
}

} // namespace

void drone_remoteid() {
    Serial.println("[DroneRID] passive Open Drone ID detector starting (RX-only)");
    drones.clear();
    ringHead = ringTail = ringDropped = 0;
    cbHits = 0;
    scroll = cursor = 0;
    detailView = false;
    fullClear = true;
    mode = MODE_WIFI;

    droneSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(DET_DIR)) SD.mkdir(DET_DIR);
        droneSd = true;
        if (!SD.exists(DRONE_CSV)) {
            File f = SD.open(DRONE_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,clock,src,addr,uas_id,ua_type,drone_lat,drone_lon,drone_alt,speed,"
                          "track,op_lat,op_lon,op_alt,rssi");
                f.close();
            }
        }
        Serial.printf("[DroneRID] logging -> %s\n", DRONE_CSV);
    } else {
        Serial.println("[DroneRID] no SD card - logging disabled");
    }

    startWifi();
    droneDraw();

    while (!check(EscPress)) {
        OdidEvent e;
        int drained = 0;
        while (drained++ < 8 && ringPop(e)) onEvent(e);

        if (mode == MODE_WIFI && millis() - lastHopMs > HOP_MS) {
            lastHopMs = millis();
            hopChannel();
        }

        if (check(SelPress)) detailView = !detailView;
        if (check(PrevPress)) {
            if (detailView) { /* single drone view */ }
            else if (cursor > 0) cursor--;
        }
        if (check(NextPress)) {
            if (!detailView) cursor++;
        }
        char ch = checkLetterShortcutPress();
        if (ch == 'm' || ch == 'M') {
            // Toggle transport. Table/model persist across the switch.
            if (mode == MODE_WIFI) {
                stopWifi();
                startBle();
                mode = MODE_BLE;
            } else {
                stopBle();
                startWifi();
                mode = MODE_WIFI;
            }
            fullClear = true;
        }

        if (Serial.available()) {
            String line = Serial.readStringUntil('\n');
            feedSerialHex(line);
        }

        droneDraw();
        delay(15);
    }

    if (mode == MODE_WIFI) stopWifi();
    else stopBle();
    Serial.printf(
        "[DroneRID] stopped. drones=%u hits=%lu dropped=%lu\n", (unsigned)drones.size(),
        (unsigned long)cbHits, (unsigned long)ringDropped
    );
}
