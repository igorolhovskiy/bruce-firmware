#include "follower_scan.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "modules/ble/ble_common.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive follower / "is something tailing me?" detector. Unifies WiFi probe-
// request source MACs and BLE advertiser addresses into one dwell-time model.
// For each address it tracks first/last-seen, dwell span, sighting count, RSSI
// trend, and a "seen across a move" flag: press SEL to mark "I moved" - any
// address seen both before and after the mark is a strong follower signal.
// Sorted by a follower score; top = most likely tail. Fully receive-only.
//
// WiFi and BLE cannot share the radio simultaneously here, so the transport is
// toggled with 'm'; the dwell model persists across the switch, so alternating
// modes accumulates both. CAVEAT (shown in-UI): modern phones randomize their
// MAC/BLE address and evade dwell tracking; fixed-address gadgets and trackers
// not separated from their owner do not.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

const uint8_t follow_channels[] = {1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
constexpr size_t N_CHANNELS = sizeof(follow_channels);

enum SrcType : uint8_t { SRC_WIFI = 1, SRC_BLE = 2 };
const char *srcTag(uint8_t s) { return s == SRC_WIFI ? "W" : "B"; }

// ── Sighting event (callback -> ring) ────────────────────────────────────────
struct SeenEvent {
    char addr[18];
    int8_t rssi;
    uint8_t src;
    bool randomized;
};

constexpr size_t RING_SZ = 96;
SeenEvent ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;

void ringPush(const SeenEvent &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(SeenEvent &e) {
    if (ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

// ── WiFi promiscuous capture (probe-request source MACs) ─────────────────────
volatile uint8_t curCh = 1;

void wifi_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;
    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 0) return;
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    if (subtype != 0x04) return; // probe requests carry the client's own address

    const uint8_t *mac = p + 10;
    SeenEvent e = {};
    snprintf(e.addr, sizeof(e.addr), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
             mac[4], mac[5]);
    e.rssi = pkt->rx_ctrl.rssi;
    e.src = SRC_WIFI;
    e.randomized = (mac[0] & 0x02) != 0; // locally-administered bit -> randomized
    ringPush(e);
}

// ── BLE passive capture (all advertisers) ────────────────────────────────────
class FollowBleCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *dev) override {
        SeenEvent e = {};
        strlcpy(e.addr, dev->getAddress().toString().c_str(), sizeof(e.addr));
        e.rssi = dev->getRSSI();
        e.src = SRC_BLE;
        e.randomized = dev->getAddressType() != 0; // non-public -> randomized
        ringPush(e);
    }
};

// ── Dwell model ──────────────────────────────────────────────────────────────
struct SeenEnt {
    char addr[18];
    uint8_t src;
    int8_t rssi, bestRssi, firstRssi;
    uint16_t count;
    uint32_t firstMs, lastMs;
    bool randomized;
    bool beforeMove; // present at the last "I moved" mark
    bool afterMove;  // seen again after that mark
};
constexpr size_t SEEN_MAX = 256;
std::vector<SeenEnt> seen;
int scroll = 0;

bool moveMarked = false;
uint32_t moveMs = 0;
int moveCount = 0;

// Follower score: dwell(s) + count + signal + big bonus for crossing a move.
long score(const SeenEnt &e) {
    long dwellS = (long)((e.lastMs - e.firstMs) / 1000);
    long sig = e.bestRssi + 100; // ~0..70
    long crossed = (e.beforeMove && e.afterMove) ? 5000 : 0;
    long randPenalty = e.randomized ? 30 : 0;
    return dwellS + e.count + sig + crossed - randPenalty;
}

// ── SD logging ───────────────────────────────────────────────────────────────
bool followSd = false;
const char *DET_DIR = "/BruceDetector";
const char *FOLLOW_CSV = "/BruceDetector/followers.csv";
String macTail(const char *addr) { return String(addr).substring(9); }

void logFollower(const SeenEnt &e, const char *event) {
    if (!followSd) return;
    File f = SD.open(FOLLOW_CSV, FILE_APPEND);
    if (!f) return;
    f.println(
        String(millis()) + "," + event + "," + srcTag(e.src) + "," + e.addr + "," +
        String((e.lastMs - e.firstMs) / 1000) + "," + String(e.count) + "," + String(e.bestRssi) + "," +
        (e.randomized ? "rand" : "fixed") + "," + ((e.beforeMove && e.afterMove) ? "crossed" : "-")
    );
    f.close();
}

void onSeen(const SeenEvent &ev) {
    for (auto &e : seen) {
        if (strcmp(e.addr, ev.addr) == 0) {
            e.rssi = ev.rssi;
            if (ev.rssi > e.bestRssi) e.bestRssi = ev.rssi;
            e.lastMs = millis();
            if (e.count < 0xFFFF) e.count++;
            if (moveMarked && e.beforeMove && !e.afterMove) {
                e.afterMove = true;
                logFollower(e, "CROSSED"); // seen again after a move -> follower
            }
            return;
        }
    }
    if (seen.size() >= SEEN_MAX) {
        size_t oldest = 0;
        for (size_t i = 1; i < seen.size(); i++)
            if (seen[i].lastMs < seen[oldest].lastMs) oldest = i;
        seen.erase(seen.begin() + oldest);
    }
    SeenEnt e = {};
    strlcpy(e.addr, ev.addr, sizeof(e.addr));
    e.src = ev.src;
    e.rssi = e.bestRssi = e.firstRssi = ev.rssi;
    e.count = 1;
    e.firstMs = e.lastMs = millis();
    e.randomized = ev.randomized;
    seen.push_back(e);
}

// Mark "I moved": snapshot which addresses were present, so a re-sighting flags
// a follower. Only currently-known entries can be "before" the move.
void markMove() {
    moveMarked = true;
    moveMs = millis();
    moveCount++;
    for (auto &e : seen) {
        e.beforeMove = true;
        e.afterMove = false;
    }
    Serial.printf("[Follower] move #%d marked; %u addrs snapshotted\n", moveCount, (unsigned)seen.size());
}

int crossedCount() {
    int c = 0;
    for (auto &e : seen)
        if (e.beforeMove && e.afterMove) c++;
    return c;
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
String fmtSpan(uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60) return String(s) + "s";
    if (s < 3600) return String(s / 60) + "m";
    return String(s / 3600) + "h" + String((s % 3600) / 60) + "m";
}
void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    if (mode == MODE_WIFI)
        snprintf(l0, sizeof(l0), "Follower  WiFi CH%u  drop:%lu", (unsigned)curCh, (unsigned long)ringDropped);
    else snprintf(l0, sizeof(l0), "Follower  BLE  drop:%lu", (unsigned long)ringDropped);
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    int cr = crossedCount();
    char l1[72];
    snprintf(
        l1, sizeof(l1), "seen:%u  moves:%d  followers:%d", (unsigned)seen.size(), moveCount, cr
    );
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(cr > 0 ? TFT_RED : TFT_GREEN, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter() {
    String hint = "SEL 'I moved'  m mode  ^v scroll  <-exit";
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

    std::vector<int> idx(seen.size());
    for (size_t i = 0; i < seen.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) { return score(seen[a]) > score(seen[b]); });

    int total = (int)idx.size();
    int maxScroll = total - rows;
    if (maxScroll < 0) maxScroll = 0;
    if (scroll > maxScroll) scroll = maxScroll;
    if (scroll < 0) scroll = 0;

    uint32_t now = millis();
    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int li = scroll + slot;
        if (li >= total) {
            if (total == 0 && slot == 0) drawRow(slot, y, "  (building dwell model...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const SeenEnt &e = seen[idx[li]];
        bool crossed = e.beforeMove && e.afterMove;
        String flags = String(crossed ? "M" : "-") + (e.randomized ? "r" : "-");
        String line = String(srcTag(e.src)) + " " + macTail(e.addr) + " " + fmtSpan(e.lastMs - e.firstMs) +
                      " x" + String(e.count) + " " + String(e.rssi) + " " + flags + " " +
                      fmtSpan(now - e.lastMs);
        uint16_t fg = crossed ? TFT_RED : (e.randomized ? TFT_DARKGREY : TFT_WHITE);
        drawRow(slot, y, line, fg);
    }
}
void followDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome();
    drawBody();
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
    curCh = follow_channels[chIdx];
    esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
    lastHopMs = millis();
}
void stopWifi() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevWifiMode);
}
void startBle() {
    ble_scan_setup();
    pBLEScan->setScanCallbacks(new FollowBleCallbacks(), true);
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
    curCh = follow_channels[chIdx];
    esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

} // namespace

void follower_scan() {
    Serial.println("[Follower] passive follower / dwell-time scan starting (RX-only)");
    seen.clear();
    ringHead = ringTail = ringDropped = 0;
    scroll = 0;
    moveMarked = false;
    moveCount = 0;
    fullClear = true;
    mode = MODE_WIFI;

    followSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(DET_DIR)) SD.mkdir(DET_DIR);
        followSd = true;
        if (!SD.exists(FOLLOW_CSV)) {
            File f = SD.open(FOLLOW_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,event,src,addr,dwell_s,count,best_rssi,addr_kind,crossed");
                f.close();
            }
        }
        Serial.printf("[Follower] logging -> %s\n", FOLLOW_CSV);
    } else {
        Serial.println("[Follower] no SD card - logging disabled");
    }

    startWifi();
    followDraw();

    while (!check(EscPress)) {
        SeenEvent ev;
        int drained = 0;
        while (drained++ < 64 && ringPop(ev)) onSeen(ev);

        if (mode == MODE_WIFI && millis() - lastHopMs > HOP_MS) {
            lastHopMs = millis();
            hopChannel();
        }

        if (check(SelPress)) markMove();
        if (check(PrevPress) && scroll > 0) scroll--;
        if (check(NextPress)) scroll++;
        char c = checkLetterShortcutPress();
        if (c == 'm' || c == 'M') {
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

        followDraw();
        delay(15);
    }

    if (mode == MODE_WIFI) stopWifi();
    else stopBle();
    Serial.printf(
        "[Follower] stopped. seen=%u moves=%d followers=%d dropped=%lu\n", (unsigned)seen.size(),
        moveCount, crossedCount(), (unsigned long)ringDropped
    );
}
