#include "ambient_watch.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "cs_classify.h"
#include "modules/ble/ble_common.h"
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <algorithm>
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
struct Event {
    char addr[18];
    int8_t rssi;
    bool ble;
    cs::Hit hit;
};
constexpr size_t RING_SZ = 48;
Event ring[RING_SZ];
volatile uint16_t ringHead = 0, ringTail = 0;
volatile uint32_t ringDropped = 0;

void ringPush(const Event &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(Event &e) {
    if (ringTail == ringHead) return false;
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
    if (subtype == 0x04) {
        mac = p + 10;
        extractSsid(p, len, 24, ssid);
    } else if (subtype == 0x08 || subtype == 0x05) {
        mac = p + 16;
        extractSsid(p, len, 36, ssid);
        beacon = true;
    } else {
        return;
    }
    wifiFrames = wifiFrames + 1;

    cs::Hit h = cs::classifyWifi(mac, ssid);
    if (!h.hit && beacon) h = cs::classifyWifiBeacon(p, len);
    if (!h.hit) return;

    Event e = {};
    macStr(mac, e.addr);
    e.rssi = pkt->rx_ctrl.rssi;
    e.ble = false;
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
        char name[24];
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
        e.rssi = dev->getRSSI();
        e.ble = true;
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
    uint8_t conf;
    bool ble;
    int8_t rssi, bestRssi;
    uint16_t count;
    uint32_t lastMs;
};
constexpr size_t THREAT_MAX = 96;
std::vector<Threat> threats;
int cursor = 0, scroll = 0;

void onEvent(const Event &ev) {
    for (auto &t : threats) {
        if (t.ble == ev.ble && strcmp(t.addr, ev.addr) == 0 && strcmp(t.kind, ev.hit.kind) == 0) {
            t.rssi = ev.rssi;
            if (ev.rssi > t.bestRssi) t.bestRssi = ev.rssi;
            if (t.count < 0xFFFF) t.count++;
            if (ev.hit.conf > t.conf) t.conf = ev.hit.conf;
            t.lastMs = millis();
            return;
        }
    }
    if (threats.size() >= THREAT_MAX) {
        size_t oldest = 0;
        for (size_t i = 1; i < threats.size(); i++)
            if (threats[i].lastMs < threats[oldest].lastMs) oldest = i;
        threats.erase(threats.begin() + oldest);
    }
    Threat t = {};
    strlcpy(t.addr, ev.addr, sizeof(t.addr));
    strlcpy(t.kind, ev.hit.kind, sizeof(t.kind));
    strlcpy(t.label, ev.hit.label, sizeof(t.label));
    t.conf = ev.hit.conf;
    t.ble = ev.ble;
    t.rssi = t.bestRssi = ev.rssi;
    t.count = 1;
    t.lastMs = millis();
    threats.push_back(t);
    Serial.printf("[Watch] %s HIT %s %s \"%s\" rssi=%d conf=%s\n", ev.ble ? "BLE" : "WIFI", ev.hit.kind,
                  ev.addr, ev.hit.label, ev.rssi, cs::confName(ev.hit.conf));
}

// ── Rendering (per-row diffed) ───────────────────────────────────────────────
constexpr int CHROME_H = 26, FOOTER_H = 12, ROW_H = 11, MAX_ROWS = 18;
String rowCache[MAX_ROWS];
uint16_t rowFgCache[MAX_ROWS];
String chromeCache[2], footerCache;
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
int highCount() {
    int c = 0;
    for (auto &t : threats)
        if (t.conf == cs::CONF_HIGH) c++;
    return c;
}
void drawChrome(bool blePhase, uint8_t ch) {
    tft.setTextSize(FP);
    char l0[64];
    if (blePhase) snprintf(l0, sizeof(l0), "Ambient Watch  [BLE] scan");
    else snprintf(l0, sizeof(l0), "Ambient Watch  [WIFI] ch%u", ch);
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    int hi = highCount();
    char l1[64];
    snprintf(l1, sizeof(l1), "threats:%u  high:%d  drop:%lu", (unsigned)threats.size(), hi,
             (unsigned long)ringDropped);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(hi > 0 ? TFT_RED : (threats.empty() ? TFT_GREEN : TFT_YELLOW), TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter() {
    String hint = "^v select  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}
void awDraw(bool blePhase, uint8_t ch) {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome(blePhase, ch);
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    std::vector<int> idx(threats.size());
    for (size_t i = 0; i < threats.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) {
        if (threats[a].conf != threats[b].conf) return threats[a].conf > threats[b].conf;
        return threats[a].bestRssi > threats[b].bestRssi;
    });
    int total = (int)idx.size();
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
        String label = String(t.label);
        if (label.length() > 14) label = label.substring(0, 14);
        char line[56];
        snprintf(line, sizeof(line), "%c%c %s %s %d x%u", li == cursor ? '>' : ' ', cflag,
                 t.kind, label.c_str(), t.rssi, t.count);
        uint16_t fg = li == cursor            ? TFT_CYAN
                      : t.conf == cs::CONF_HIGH ? TFT_RED
                      : t.conf == cs::CONF_MED  ? TFT_YELLOW
                                                : TFT_DARKGREY;
        drawRow(slot, y, line, fg);
    }
    drawFooter();
}

// ── Radio phase control ──────────────────────────────────────────────────────
void startWifiPhase(uint8_t chIdx) {
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wifi_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(wifi_channels[chIdx], WIFI_SECOND_CHAN_NONE);
}
void stopWifiPhase() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
}
void startBlePhase() {
    ble_scan_setup(); // tears down WiFi, inits BLE
    pBLEScan->setScanCallbacks(&bleCb, false);
    pBLEScan->setActiveScan(false);
    pBLEScan->setMaxResults(0);
    pBLEScan->start(0, false);
}
void stopBlePhase() {
    if (pBLEScan) pBLEScan->stop();
    stopBLEStack();
}

} // namespace

void ambient_watch() {
    Serial.println("[Watch] Ambient Watch starting (passive, time-sliced WiFi<->BLE)");
    cs::runCsClassifySelfTest();

    threats.clear();
    ringHead = ringTail = ringDropped = 0;
    wifiFrames = 0;
    cursor = scroll = 0;
    fullClear = true;

    wifi_mode_t prevMode = WiFi.getMode();

    constexpr uint32_t WIFI_PHASE_MS = 8000;
    constexpr uint32_t BLE_PHASE_MS = 6000;
    constexpr uint32_t HOP_MS = 350;

    bool blePhase = false;
    uint8_t chIdx = 0;
    startWifiPhase(chIdx);
    uint32_t phaseStart = millis(), lastHop = millis();
    awDraw(blePhase, wifi_channels[chIdx]);

    while (!check(EscPress)) {
        Event ev;
        int drained = 0;
        while (drained++ < 32 && ringPop(ev)) onEvent(ev);

        uint32_t now = millis();
        // WiFi channel hop within the WiFi phase.
        if (!blePhase && now - lastHop > HOP_MS) {
            lastHop = now;
            chIdx = (chIdx + 1) % N_WIFI_CH;
            esp_wifi_set_channel(wifi_channels[chIdx], WIFI_SECOND_CHAN_NONE);
        }
        // Phase switch.
        uint32_t phaseLen = blePhase ? BLE_PHASE_MS : WIFI_PHASE_MS;
        if (now - phaseStart > phaseLen) {
            if (blePhase) {
                stopBlePhase();
                chIdx = 0;
                startWifiPhase(chIdx);
                blePhase = false;
            } else {
                stopWifiPhase();
                startBlePhase();
                blePhase = true;
            }
            phaseStart = millis();
            lastHop = millis();
            fullClear = true;
            Serial.printf("[Watch] phase -> %s\n", blePhase ? "BLE" : "WIFI");
        }

        if (check(PrevPress) && cursor > 0) cursor--;
        if (check(NextPress)) cursor++;

        awDraw(blePhase, wifi_channels[chIdx]);
        delay(15);
    }

    if (blePhase) stopBlePhase();
    else stopWifiPhase();
    WiFi.mode(prevMode);
    Serial.printf("[Watch] stopped. threats=%u wifiFrames=%lu dropped=%lu\n",
                  (unsigned)threats.size(), (unsigned long)wifiFrames, (unsigned long)ringDropped);
}
