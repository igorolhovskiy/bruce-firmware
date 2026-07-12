#include "blockack_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include <WiFi.h>
#include <algorithm>
#include <esp_wifi.h>
#include <globals.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Passive Block-Ack (BAR) flood detector. Same capture substrate as the WiFi
// camera detector, but the promiscuous filter admits *control* frames and the
// callback keeps only Block Ack Requests (type=control, subtype=8). Each BAR is
// pushed through a ring to the main loop, which dedups by transmitter (TA) and
// tracks a per-second BAR rate, broadcast-RA usage and Starting-Sequence-Number
// jumps. Legitimate BAR is sparse; a TA emitting BAR at high rate is the "Bl0ck"
// signature (arXiv:2302.05899) — an attack that survives 802.11w/PMF where a
// classic deauth would be dropped. Per-row diffed draw, serial mirror, SD log.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

const uint8_t ba_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
constexpr size_t N_CHANNELS = sizeof(ba_channels);

// BAR frames/second from one TA above which we call it an attack. Legitimate BAR
// is bursty but rare over a window; a flood sits well above this.
constexpr uint16_t BAR_FLOOD_RATE = 12;

// ── Capture event (callback -> ring) ─────────────────────────────────────────
struct BaEvent {
    uint8_t ta[6];
    uint8_t ra[6];
    uint16_t ssn;
    int8_t rssi;
    uint8_t ch;
    bool bcastRa;
};

constexpr size_t RING_SZ = 128;
BaEvent ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;
volatile uint32_t cbBars = 0;

void ringPush(const BaEvent &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(BaEvent &e) {
    if (ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

bool isBroadcast(const uint8_t *m) {
    return (m[0] & m[1] & m[2] & m[3] & m[4] & m[5]) == 0xFF;
}

void ba_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_CTRL) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 20) return;

    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 0x01) return; // control frames only
    if (((fc0 >> 4) & 0x0F) != 0x08) return; // BlockAckReq subtype only

    BaEvent e = {};
    memcpy(e.ra, p + 4, 6);  // RA = receiver
    memcpy(e.ta, p + 10, 6); // TA = transmitter (the spoofed AP in an attack)
    uint16_t ssc = (uint16_t)(p[18] | (p[19] << 8));
    e.ssn = (ssc >> 4) & 0x0FFF;
    e.rssi = pkt->rx_ctrl.rssi;
    e.ch = pkt->rx_ctrl.channel;
    e.bcastRa = isBroadcast(e.ra);
    cbBars = cbBars + 1;
    ringPush(e);
}

// ── Table ────────────────────────────────────────────────────────────────────
struct BaEnt {
    uint8_t ta[6];
    uint8_t lastRa[6];
    bool bcastRa;
    uint16_t lastSsn;
    uint16_t maxJump;
    int8_t rssi;
    int8_t bestRssi;
    uint8_t ch;
    uint32_t count;
    uint16_t bucket; // BARs seen in the current 1s window
    uint16_t rate;   // BARs/s from the last completed window
    uint32_t firstMs;
    uint32_t lastMs;
    bool flagged;
};
constexpr size_t BA_MAX = 96;
std::vector<BaEnt> tas;

int scroll = 0;
int cursor = 0;

// Channel hop state.
size_t chIdx = 0;
bool chLocked = false;
uint32_t lastHopMs = 0;
constexpr uint32_t HOP_MS = 300;

// ── SD logging ───────────────────────────────────────────────────────────────
bool baSd = false;
const char *DET_DIR = "/BruceDetector";
const char *BA_CSV = "/BruceDetector/blockack.csv";

String macStr(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
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

void logSighting(const BaEvent &e) {
    if (!baSd) return;
    File f = SD.open(BA_CSV, FILE_APPEND);
    if (!f) return;
    f.println(
        String(millis()) + "," + nowClk() + "," + macStr(e.ta) + "," + macStr(e.ra) + "," +
        String(e.ssn) + "," + String(e.rssi) + "," + String(e.ch) + "," +
        String(e.bcastRa ? "bcast" : "unicast")
    );
    f.close();
}

// ── Model update (main loop) ─────────────────────────────────────────────────
bool sameMac(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

void onBar(const BaEvent &e) {
    for (auto &c : tas) {
        if (sameMac(c.ta, e.ta)) {
            uint16_t jump = (uint16_t)((e.ssn - c.lastSsn) & 0x0FFF);
            if (jump > 0 && jump < 0x0800 && jump > c.maxJump) c.maxJump = jump;
            c.lastSsn = e.ssn;
            memcpy(c.lastRa, e.ra, 6);
            c.bcastRa = c.bcastRa || e.bcastRa;
            c.rssi = e.rssi;
            if (e.rssi > c.bestRssi) c.bestRssi = e.rssi;
            c.ch = e.ch;
            c.lastMs = millis();
            if (c.count < 0xFFFFFF) c.count++;
            if (c.bucket < 0xFFFF) c.bucket++;
            logSighting(e);
            return;
        }
    }
    if (tas.size() >= BA_MAX) {
        size_t oldest = 0;
        for (size_t i = 1; i < tas.size(); i++)
            if (tas[i].lastMs < tas[oldest].lastMs) oldest = i;
        tas.erase(tas.begin() + oldest);
    }
    BaEnt c = {};
    memcpy(c.ta, e.ta, 6);
    memcpy(c.lastRa, e.ra, 6);
    c.bcastRa = e.bcastRa;
    c.lastSsn = e.ssn;
    c.maxJump = 0;
    c.rssi = c.bestRssi = e.rssi;
    c.ch = e.ch;
    c.count = 1;
    c.bucket = 1;
    c.rate = 0;
    c.firstMs = c.lastMs = millis();
    c.flagged = false;
    tas.push_back(c);
    logSighting(e);
    Serial.printf(
        "[BlockAckDet] BAR ta=%s ra=%s ssn=%u ch=%u%s\n", macStr(e.ta).c_str(), macStr(e.ra).c_str(),
        e.ssn, e.ch, e.bcastRa ? " (bcast RA)" : ""
    );
}

// Roll the 1-second rate buckets and (re)evaluate the flood flag.
void rollRates() {
    for (auto &c : tas) {
        c.rate = c.bucket;
        c.bucket = 0;
        bool wasFlagged = c.flagged;
        c.flagged = (c.rate >= BAR_FLOOD_RATE) || (c.bcastRa && c.rate >= BAR_FLOOD_RATE / 2);
        if (c.flagged && !wasFlagged)
            Serial.printf(
                "[BlockAckDet] *** BAR FLOOD *** ta=%s rate=%u/s ch=%u maxJump=%u%s\n",
                macStr(c.ta).c_str(), c.rate, c.ch, c.maxJump, c.bcastRa ? " bcastRA" : ""
            );
    }
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

int flaggedCount() {
    int c = 0;
    for (auto &e : tas)
        if (e.flagged) c++;
    return c;
}

void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(
        l0, sizeof(l0), "BAR Detect  CH%02u%s  drop:%lu", ba_channels[chIdx], chLocked ? "[L]" : "   ",
        (unsigned long)ringDropped
    );
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    int fl = flaggedCount();
    char l1[64];
    snprintf(l1, sizeof(l1), "TAs:%u  floods:%d  BARs:%lu", (unsigned)tas.size(), fl,
             (unsigned long)cbBars);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(fl > 0 ? TFT_RED : (tas.empty() ? TFT_GREEN : TFT_YELLOW), TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}

void drawFooter() {
    String hint = "^v select  l lock ch  <- exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

void buildOrder(std::vector<int> &idx) {
    idx.resize(tas.size());
    for (size_t i = 0; i < tas.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) {
        // Flagged first, then by BAR rate, then by strongest RSSI.
        const BaEnt &A = tas[a], &B = tas[b];
        if (A.flagged != B.flagged) return A.flagged;
        if (A.rate != B.rate) return A.rate > B.rate;
        return A.bestRssi > B.bestRssi;
    });
}

void drawBody() {
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
                drawRow(slot, y, "  (listening for BAR floods...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const BaEnt &c = tas[idx[li]];
        String taTail = macStr(c.ta).substring(9); // last 3 octets
        String line = String(li == cursor ? '>' : ' ') + String(c.flagged ? '!' : ' ') + " " + taTail +
                      " c" + String(c.ch) + " " + String(c.rate) + "/s x" + String(c.count) +
                      (c.bcastRa ? " bc" : "") + " " + String(c.rssi);
        uint16_t fg = li == cursor ? TFT_CYAN : c.flagged ? TFT_RED : TFT_DARKGREY;
        drawRow(slot, y, line, fg);
    }
}

void baDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome();
    drawBody();
    drawFooter();
}

void hopChannel() {
    esp_wifi_set_promiscuous(false);
    chIdx = (chIdx + 1) % N_CHANNELS;
    esp_wifi_set_channel(ba_channels[chIdx], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

void dumpTableSerial() {
    Serial.printf("[BlockAckDet] table (%u transmitters):\n", (unsigned)tas.size());
    for (auto &c : tas) {
        Serial.printf(
            "  ta=%s ra=%s ch%u rate=%u/s x%lu maxJump=%u rssi=%d(best%d) %s%s\n",
            macStr(c.ta).c_str(), macStr(c.lastRa).c_str(), c.ch, c.rate, (unsigned long)c.count,
            c.maxJump, c.rssi, c.bestRssi, c.bcastRa ? "bcastRA " : "", c.flagged ? "<<FLOOD" : ""
        );
    }
}

} // namespace

void blockack_detector() {
    Serial.println("[BlockAckDet] passive Block-Ack flood detector starting (RX-only)");
    tas.clear();
    ringHead = 0;
    ringTail = 0;
    ringDropped = 0;
    cbBars = 0;
    scroll = 0;
    cursor = 0;
    chIdx = 0;
    chLocked = false;
    fullClear = true;

    baSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(DET_DIR)) SD.mkdir(DET_DIR);
        baSd = true;
        if (!SD.exists(BA_CSV)) {
            File f = SD.open(BA_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,clock,ta,ra,ssn,rssi,channel,ra_type");
                f.close();
            }
        }
        Serial.printf("[BlockAckDet] logging -> %s\n", BA_CSV);
    } else {
        Serial.println("[BlockAckDet] no SD card - logging disabled");
    }

    // Promiscuous RX in STA mode; admit control frames and keep all control
    // subtypes so BlockAckReq reaches the callback.
    wifi_mode_t prevMode = WiFi.getMode();
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL};
    esp_wifi_set_promiscuous_filter(&filter);
    wifi_promiscuous_filter_t ctrlFilter = {.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL};
    esp_wifi_set_promiscuous_ctrl_filter(&ctrlFilter);
    esp_wifi_set_promiscuous_rx_cb(ba_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(ba_channels[chIdx], WIFI_SECOND_CHAN_NONE);

    baDraw();
    lastHopMs = millis();
    uint32_t lastRoll = millis();

    while (true) {
        BaEvent e;
        int drained = 0;
        while (drained++ < 128 && ringPop(e)) onBar(e);

        if (millis() - lastRoll >= 1000) {
            lastRoll = millis();
            rollRates();
        }

        if (!chLocked && millis() - lastHopMs > HOP_MS) {
            lastHopMs = millis();
            hopChannel();
        }

        if (check(EscPress)) break;
        if (check(PrevPress) && cursor > 0) cursor--;
        if (check(NextPress)) cursor++;
        char ch = checkLetterShortcutPress();
        if (ch == 'l' || ch == 'L') chLocked = !chLocked;

        if (Serial.available()) {
            while (Serial.available()) Serial.read();
            dumpTableSerial();
        }

        baDraw();
        delay(15);
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevMode);
    Serial.printf(
        "[BlockAckDet] stopped. transmitters=%u floods=%d bars=%lu dropped=%lu\n",
        (unsigned)tas.size(), flaggedCount(), (unsigned long)cbBars, (unsigned long)ringDropped
    );
}
