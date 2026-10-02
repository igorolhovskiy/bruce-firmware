#include "stream_cam_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <WiFi.h>
#include <algorithm>
#include <esp_wifi.h>
#include <globals.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 of the traffic-pattern camera detector (bruce-stream-camera-TASK.md).
// Passive promiscuous capture of 802.11 DATA frames; per-station (addr2) tally of
// frame count / large-frame count / upstream count / span; a pure scorer flags
// video-like flows. Slow per-channel dwell (seconds) so a camera accumulates a
// usable sample. Receive-only; restores WiFi mode on exit. No payload is read.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

enum Conf : uint8_t { SC_NONE = 0, SC_LOW = 1, SC_MED = 2 };
const char *confName(uint8_t c) { return c == SC_MED ? "MED" : c == SC_LOW ? "LOW" : "-"; }

// "Large" data frame (video MPDUs run near the MTU; control/ACKs are tiny).
constexpr uint16_t LARGE_BYTES = 1000;

// Per-station stats. Updated in the RX callback; read in the loop. A fixed array
// (no realloc) avoids a vector reallocating under the callback.
struct Station {
    uint8_t mac[6];
    uint8_t ch;
    volatile uint32_t dataFrames;
    volatile uint32_t largeFrames;
    volatile uint32_t upstreamFrames;
    uint32_t firstMs;
    volatile uint32_t lastMs;
};
constexpr size_t MAX_ST = 64;
Station stations[MAX_ST];
volatile int stationCount = 0;
volatile uint32_t curMs = 0; // millis() mirrored for the ISR to stamp

// Pure scorer: classify one station's accumulated stats. Kept free of radio/
// display so it unit-tests offline (see runStreamCamSelfTest).
uint8_t scoreStation(uint32_t dataFrames, uint32_t largeFrames, uint32_t upstreamFrames,
                     uint32_t spanMs) {
    if (spanMs < 1500 || dataFrames < 40) return SC_NONE; // need a sustained sample
    uint32_t rate = dataFrames * 1000UL / spanMs;         // data frames / second
    uint32_t largePct = largeFrames * 100UL / dataFrames;
    uint32_t upPct = upstreamFrames * 100UL / dataFrames;
    if (rate < 15 || largePct < 40 || upPct < 60) return SC_NONE; // not video-like
    if (rate >= 30 && largePct >= 55) return SC_MED;
    return SC_LOW;
}

uint8_t curChannel = 1;

void IRAM_ATTR sc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;
    uint8_t fc1 = p[1];
    bool toDS = fc1 & 0x01;
    bool fromDS = fc1 & 0x02;
    const uint8_t *tx = p + 10; // addr2 = transmitter (the station, on an uplink)
    bool upstream = toDS && !fromDS;
    bool large = len > LARGE_BYTES;

    int n = stationCount;
    for (int i = 0; i < n; i++) {
        if (memcmp(stations[i].mac, tx, 6) == 0) {
            stations[i].dataFrames++;
            if (large) stations[i].largeFrames++;
            if (upstream) stations[i].upstreamFrames++;
            stations[i].lastMs = curMs;
            return;
        }
    }
    if (n >= (int)MAX_ST) return; // table full: ignore new stations this session
    // Append: fill fields BEFORE publishing the new count (lock-free pattern).
    memcpy(stations[n].mac, tx, 6);
    stations[n].ch = curChannel;
    stations[n].dataFrames = 1;
    stations[n].largeFrames = large ? 1 : 0;
    stations[n].upstreamFrames = upstream ? 1 : 0;
    stations[n].firstMs = curMs;
    stations[n].lastMs = curMs;
    stationCount = n + 1;
}

// ── Rendering (per-row diffed) ───────────────────────────────────────────────
constexpr int CHROME_H = 26, FOOTER_H = 12, ROW_H = 11, MAX_ROWS = 18;
String rowCache[MAX_ROWS];
uint16_t rowFgCache[MAX_ROWS];
String chromeCache[2], footerCache;
bool fullClear = true;
int cursor = 0, scroll = 0;

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

struct Cand {
    int idx;
    uint8_t conf;
    uint32_t rate;
    uint32_t largePct;
};
void buildCandidates(std::vector<Cand> &out) {
    int n = stationCount;
    for (int i = 0; i < n; i++) {
        uint32_t df = stations[i].dataFrames, lf = stations[i].largeFrames,
                 uf = stations[i].upstreamFrames;
        uint32_t span = stations[i].lastMs - stations[i].firstMs;
        uint8_t c = scoreStation(df, lf, uf, span);
        if (c == SC_NONE) continue;
        uint32_t rate = span ? df * 1000UL / span : 0;
        uint32_t lpct = df ? lf * 100UL / df : 0;
        out.push_back({i, c, rate, lpct});
    }
    std::sort(out.begin(), out.end(), [](const Cand &a, const Cand &b) {
        if (a.conf != b.conf) return a.conf > b.conf;
        return a.rate > b.rate;
    });
}

void drawChrome(int candCount) {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(l0, sizeof(l0), "Stream Cam  ch%u  stations:%d", curChannel, stationCount);
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    char l1[64];
    snprintf(l1, sizeof(l1), "video-like candidates: %d", candCount);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(candCount ? TFT_RED : TFT_GREEN, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter() {
    String hint = "^v select  <-exit  (heuristic)";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}
void scDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    std::vector<Cand> cands;
    buildCandidates(cands);
    drawChrome((int)cands.size());

    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;
    int total = (int)cands.size();
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
            if (total == 0 && slot == 0)
                drawRow(slot, y, "  (watching traffic, dwell/chan...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const Cand &c = cands[li];
        const Station &s = stations[c.idx];
        char line[56];
        snprintf(line, sizeof(line), "%c%c %02X%02X:%02X%02X ch%u %lu/s %lu%%L",
                 li == cursor ? '>' : ' ', c.conf == SC_MED ? 'M' : 'L', s.mac[2], s.mac[3], s.mac[4],
                 s.mac[5], s.ch, (unsigned long)c.rate, (unsigned long)c.largePct);
        uint16_t fg = li == cursor ? TFT_CYAN : c.conf == SC_MED ? TFT_RED : TFT_YELLOW;
        drawRow(slot, y, line, fg);
    }
    drawFooter();
}

// ── Offline self-test ──────────────────────────────────────────────────────────
bool runStreamCamSelfTest() {
    // Camera-like: 300 frames over 5s (60/s), 70% large, 80% upstream -> candidate.
    uint8_t cam = scoreStation(300, 210, 240, 5000);
    // Web-like: 300 frames over 5s but bursty/downstream, 20% large, 20% upstream.
    uint8_t web = scoreStation(300, 60, 60, 5000);
    // Too-short sample: should not score.
    uint8_t brief = scoreStation(300, 210, 240, 800);
    bool ok = (cam != SC_NONE) && (web == SC_NONE) && (brief == SC_NONE);
    Serial.printf("[StreamCam] self-test %s (cam=%s web=%s brief=%s)\n", ok ? "PASS" : "FAIL",
                  confName(cam), confName(web), confName(brief));
    return ok;
}

} // namespace

void stream_cam_detector() {
    Serial.println("[StreamCam] traffic-pattern camera detector starting (passive, RX-only)");
    runStreamCamSelfTest();

    stationCount = 0;
    cursor = scroll = 0;
    fullClear = true;

    wifi_mode_t prevMode = WiFi.getMode();
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(sc_cb);
    esp_wifi_set_promiscuous(true);

    const uint8_t channels[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
    const size_t NCH = sizeof(channels);
    constexpr uint32_t DWELL_MS = 4000; // slow dwell: traffic analysis needs seconds
    size_t chIdx = 0;
    curChannel = channels[chIdx];
    esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
    uint32_t dwellStart = millis();
    curMs = millis();
    scDraw();

    while (!check(EscPress)) {
        curMs = millis();
        if (curMs - dwellStart > DWELL_MS) {
            chIdx = (chIdx + 1) % NCH;
            curChannel = channels[chIdx];
            esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
            dwellStart = curMs;
        }
        if (check(PrevPress) && cursor > 0) cursor--;
        if (check(NextPress)) cursor++;
        scDraw();
        delay(30);
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevMode);
    Serial.printf("[StreamCam] stopped. stations=%d\n", stationCount);
}
