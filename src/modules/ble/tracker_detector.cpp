#include "tracker_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "modules/ble/ble_common.h"
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive BLE unwanted-tracker detector. Continuous *passive* scan (no scan
// requests sent) classifies each advertisement against known tracker signatures.
// The NimBLE scan callback runs in the host task, so it only parses + pushes a
// compact sighting to a single-producer ring; the main loop drains it, updates
// the table, logs raw data to SD, and draws.
//
// Known limitation: AirTags (and other trackers) rotate their BLE address ~every
// 15 min while separated from their owner, so one physical tag can appear as
// several rows. The raw SD log (timestamped) lets you correlate across rotations
// offline; a persistent follower still stands out by dwell time and RSSI.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

enum TrackerType : uint8_t { TR_FINDMY = 0, TR_SMARTTAG = 1, TR_TILE = 2 };

const char *typeName(uint8_t t) {
    switch (t) {
    case TR_FINDMY: return "FindMy";
    case TR_SMARTTAG: return "SmTag";
    case TR_TILE: return "Tile";
    default: return "?";
    }
}

struct Sighting {
    uint8_t type;
    uint8_t separated; // Apple Find My: 1 if broadcasting the long "separated from owner" frame
    int8_t rssi;
    uint32_t atMs;
    char addr[18];
    uint8_t payloadLen;
    uint8_t payload[31];
};

// Single-producer (scan callback) / single-consumer (loop) ring.
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

// Classify an advertisement's raw payload against tracker signatures.
// Returns true and sets type/separated if it matches a known tracker.
bool classifyPayload(const uint8_t *pl, size_t n, uint8_t &type, uint8_t &separated) {
    bool findmy = false, tile = false, smarttag = false;
    separated = 0;
    size_t i = 0;
    while (i + 1 < n) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > n) break;
        uint8_t t = pl[i + 1];
        const uint8_t *d = &pl[i + 2];
        uint8_t dl = len - 1;
        if (t == 0xFF && dl >= 3 && d[0] == 0x4C && d[1] == 0x00) {
            // Apple manufacturer data: subtypes follow the 2-byte company ID.
            size_t k = 2;
            while (k + 1 < dl) {
                uint8_t at = d[k], al = d[k + 1];
                if (k + 2 + al > dl) break;
                if (at == 0x12) { // Find My
                    findmy = true;
                    if (al >= 0x19) separated = 1; // long frame = separated from owner
                }
                k += 2 + al;
            }
        } else if ((t == 0x16 || t == 0x20 || t == 0x21) && dl >= 2) {
            uint16_t uuid = d[0] | (d[1] << 8); // service data: 16-bit UUID first
            if (uuid == 0xFEED || uuid == 0xFEEC) tile = true;
            else if (uuid == 0xFD5A) smarttag = true;
        } else if ((t == 0x02 || t == 0x03) && dl >= 2) {
            for (uint8_t o = 0; o + 1 < dl; o += 2) { // 16-bit service UUID list
                uint16_t uuid = d[o] | (d[o + 1] << 8);
                if (uuid == 0xFEED || uuid == 0xFEEC) tile = true;
                else if (uuid == 0xFD5A) smarttag = true;
            }
        }
        i += 1 + len;
    }
    if (findmy) { type = TR_FINDMY; return true; }
    if (smarttag) { type = TR_SMARTTAG; return true; }
    if (tile) { type = TR_TILE; return true; }
    return false;
}

class TrackerCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *dev) override {
        const std::vector<uint8_t> &pl = dev->getPayload();
        uint8_t type, sep;
        if (!classifyPayload(pl.data(), pl.size(), type, sep)) return;
        Sighting s = {};
        s.type = type;
        s.separated = sep;
        s.rssi = dev->getRSSI();
        s.atMs = millis();
        strlcpy(s.addr, dev->getAddress().toString().c_str(), sizeof(s.addr));
        s.payloadLen = pl.size() > 31 ? 31 : (uint8_t)pl.size();
        memcpy(s.payload, pl.data(), s.payloadLen);
        ringPush(s);
    }
};

// ── Table ───────────────────────────────────────────────────────────────────
struct TrackerEnt {
    char addr[18];
    uint8_t type;
    uint8_t separated;
    int8_t rssi;     // last
    int8_t bestRssi; // strongest (closest approach)
    uint16_t count;
    uint32_t firstMs;
    uint32_t lastMs;
    uint8_t payloadLen;   // last raw advertisement (for the detail "why" view)
    uint8_t payload[31];
};
constexpr size_t TRACKER_MAX = 128;
std::vector<TrackerEnt> trackers;

enum SortMode : uint8_t { SORT_DURATION = 0, SORT_LASTSEEN = 1, SORT_COUNT = 2 };
SortMode sortMode = SORT_DURATION;
const char *sortName(uint8_t m) {
    return m == SORT_DURATION ? "seen-time" : m == SORT_LASTSEEN ? "last-seen" : "count";
}
int scroll = 0;
int cursor = 0;          // selected row (index into the sorted display order)
bool detailView = false; // showing the per-tracker detail page for `cursor`

// A tracker seen for at least this long is flagged as a potential follower.
constexpr uint32_t PERSIST_MS = 5UL * 60 * 1000;

// ── SD logging ──────────────────────────────────────────────────────────────
bool trackerSd = false;
const char *TRACK_DIR = "/BruceTrackers";
const char *TRACK_CSV = "/BruceTrackers/trackers.csv";

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

String toHex(const uint8_t *d, size_t n) {
    static const char *H = "0123456789ABCDEF";
    String s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s += H[d[i] >> 4];
        s += H[d[i] & 0x0F];
    }
    return s;
}

void logSighting(const Sighting &s) {
    if (!trackerSd) return;
    File f = SD.open(TRACK_CSV, FILE_APPEND);
    if (!f) return;
    f.print(String(millis()) + "," + nowClk() + "," + typeName(s.type) + "," + s.addr + "," +
            String(s.rssi) + "," + (s.separated ? "1" : "0") + ",");
    f.println(toHex(s.payload, s.payloadLen));
    f.close();
}

// ── Model update (main loop) ────────────────────────────────────────────────
void onSighting(const Sighting &s) {
    for (auto &e : trackers) {
        if (strcmp(e.addr, s.addr) == 0) {
            e.rssi = s.rssi;
            if (s.rssi > e.bestRssi) e.bestRssi = s.rssi;
            e.lastMs = s.atMs;
            if (e.count < 0xFFFF) e.count++;
            if (s.separated) e.separated = 1;
            e.payloadLen = s.payloadLen;
            memcpy(e.payload, s.payload, s.payloadLen);
            logSighting(s);
            return;
        }
    }
    if (trackers.size() >= TRACKER_MAX) { // evict least-recently-seen
        size_t oldest = 0;
        for (size_t i = 1; i < trackers.size(); i++)
            if (trackers[i].lastMs < trackers[oldest].lastMs) oldest = i;
        trackers.erase(trackers.begin() + oldest);
    }
    TrackerEnt e = {};
    strlcpy(e.addr, s.addr, sizeof(e.addr));
    e.type = s.type;
    e.separated = s.separated;
    e.rssi = e.bestRssi = s.rssi;
    e.count = 1;
    e.firstMs = e.lastMs = s.atMs;
    e.payloadLen = s.payloadLen;
    memcpy(e.payload, s.payload, s.payloadLen);
    trackers.push_back(e);
    logSighting(s);
}

// ── Rendering (per-row diffed) ──────────────────────────────────────────────
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

String fmtSpan(uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60) return String(s) + "s";
    if (s < 3600) return String(s / 60) + "m";
    return String(s / 3600) + "h" + String((s % 3600) / 60) + "m";
}

// Count trackers persistent enough to flag as potential followers.
int persistentCount() {
    int c = 0;
    for (auto &e : trackers)
        if (e.lastMs - e.firstMs >= PERSIST_MS) c++;
    return c;
}

void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    int pers = persistentCount();
    snprintf(l0, sizeof(l0), "Tracker Detector  trackers:%u  drop:%lu", (unsigned)trackers.size(),
             (unsigned long)ringDropped);
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    char l1[64];
    snprintf(l1, sizeof(l1), "sort:%s  following:%d", sortName(sortMode), pers);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(pers > 0 ? TFT_RED : TFT_GREEN, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}

void drawFooter() {
    String hint = detailView ? "<-/SEL back  ^v scroll" : "SEL details  ^v select  s sort  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

// Full product name for the detail header.
const char *typeLongName(uint8_t t) {
    switch (t) {
    case TR_FINDMY: return "Apple Find My (AirTag)";
    case TR_SMARTTAG: return "Samsung SmartTag";
    case TR_TILE: return "Tile";
    default: return "Unknown tracker";
    }
}

// The advertisement signature that classified this tracker (the "why").
const char *typeSignature(uint8_t t) {
    switch (t) {
    case TR_FINDMY: return "Apple mfg-data 4C00, type 0x12";
    case TR_SMARTTAG: return "service UUID 0xFD5A";
    case TR_TILE: return "service UUID 0xFEED/0xFEEC";
    default: return "-";
    }
}

// Build the sorted display order (shared by table + detail so `cursor` maps to
// the same tracker in both).
void buildTrackerOrder(std::vector<int> &idx) {
    idx.resize(trackers.size());
    for (size_t i = 0; i < trackers.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) {
        const TrackerEnt &A = trackers[a], &B = trackers[b];
        if (sortMode == SORT_DURATION) return (A.lastMs - A.firstMs) > (B.lastMs - B.firstMs);
        if (sortMode == SORT_LASTSEEN) return A.lastMs > B.lastMs;
        return A.count > B.count;
    });
}

void drawBody() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    std::vector<int> idx;
    buildTrackerOrder(idx);
    uint32_t now = millis();

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
            if (total == 0 && slot == 0) drawRow(slot, y, "  (listening for trackers...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const TrackerEnt &e = trackers[idx[li]];
        uint32_t dur = e.lastMs - e.firstMs;
        // cursor, type (+! if Apple separated), MAC tail, dwell time, count, last-seen ago, rssi
        String tail = String(e.addr).substring(9); // last 3 octets "cc:dd:ee"... keep short
        String line = String(li == cursor ? '>' : ' ') + String(typeName(e.type)) +
                      (e.separated ? "!" : " ") + " " + tail + "  " + fmtSpan(dur) + " x" +
                      String(e.count) + " " + fmtSpan(now - e.lastMs) + " " + String(e.rssi);
        uint16_t fg = li == cursor        ? TFT_CYAN
                      : (dur >= PERSIST_MS) ? TFT_RED
                      : (e.separated)       ? TFT_YELLOW
                                            : TFT_WHITE;
        drawRow(slot, y, line, fg);
    }
}

// Per-tracker detail page: full BLE address, the recognised product, the exact
// advertisement signature that matched (the "why"), dwell stats and the raw
// advertisement bytes. Also states the address-rotation caveat.
void drawDetail() {
    std::vector<int> idx;
    buildTrackerOrder(idx);
    if (idx.empty()) {
        drawRow(0, CHROME_H, "  (no tracker selected)", TFT_DARKGREY);
        for (int s = 1; s < MAX_ROWS; s++) drawRow(s, CHROME_H + s * ROW_H, "", TFT_WHITE);
        return;
    }
    if (cursor >= (int)idx.size()) cursor = idx.size() - 1;
    if (cursor < 0) cursor = 0;
    const TrackerEnt &e = trackers[idx[cursor]];
    uint32_t now = millis();

    String lines[MAX_ROWS];
    uint16_t fgs[MAX_ROWS];
    for (int i = 0; i < MAX_ROWS; i++) { lines[i] = ""; fgs[i] = TFT_WHITE; }
    int n = 0;
    bool persistent = (e.lastMs - e.firstMs) >= PERSIST_MS;

    lines[n] = String("Addr: ") + e.addr; fgs[n++] = TFT_WHITE;
    lines[n] = String("Type: ") + typeLongName(e.type); fgs[n++] = TFT_CYAN;
    if (e.type == TR_FINDMY) {
        lines[n] = String("State: ") + (e.separated ? "SEPARATED from owner" : "with owner");
        fgs[n++] = e.separated ? TFT_YELLOW : TFT_WHITE;
    }
    lines[n] = String("RSSI: ") + e.rssi + " (best " + e.bestRssi + ")"; fgs[n++] = TFT_WHITE;
    lines[n] = String("Seen x") + e.count + "  dwell " + fmtSpan(e.lastMs - e.firstMs); fgs[n++] = TFT_WHITE;
    lines[n] = String("Last seen ") + fmtSpan(now - e.lastMs) + " ago"; fgs[n++] = TFT_WHITE;
    lines[n] = String("Following: ") + (persistent ? "YES (>5 min dwell)" : "not yet");
    fgs[n++] = persistent ? TFT_RED : TFT_GREEN;
    lines[n] = ""; fgs[n++] = TFT_WHITE;
    lines[n] = "Why flagged:"; fgs[n++] = bruceConfig.priColor;
    lines[n] = String("- ") + typeSignature(e.type); fgs[n++] = TFT_WHITE;
    if (e.type == TR_FINDMY && e.separated)
        lines[n] = "- long frame = separated tag"; else lines[n] = "";
    fgs[n++] = TFT_WHITE;
    // Raw advertisement bytes (first 20 for width), then the rotation caveat.
    if (e.payloadLen) {
        uint8_t shown = e.payloadLen > 20 ? 20 : e.payloadLen;
        lines[n] = String("Adv: ") + toHex(e.payload, shown); fgs[n++] = TFT_DARKGREY;
    }
    lines[n] = "Note: BLE addr rotates ~15min"; fgs[n++] = TFT_DARKGREY;

    for (int slot = 0; slot < MAX_ROWS; slot++)
        drawRow(slot, CHROME_H + slot * ROW_H, lines[slot], fgs[slot]);
}

void trackerDraw() {
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

} // namespace

void tracker_detector() {
    Serial.println("[Tracker] passive unwanted-tracker detector starting");
    trackers.clear();
    ringHead = 0;
    ringTail = 0;
    ringDropped = 0;
    sortMode = SORT_DURATION;
    scroll = 0;
    cursor = 0;
    detailView = false;
    fullClear = true;

    // SD logging (best-effort). Write header on first create.
    trackerSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(TRACK_DIR)) SD.mkdir(TRACK_DIR);
        trackerSd = true;
        if (!SD.exists(TRACK_CSV)) {
            File f = SD.open(TRACK_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,clock,type,mac,rssi,separated,raw_adv_hex");
                f.close();
            }
        }
        Serial.printf("[Tracker] logging -> %s\n", TRACK_CSV);
    } else {
        Serial.println("[Tracker] no SD card - logging disabled");
    }

    // Continuous PASSIVE scan (we never send scan requests -> fully receive-only).
    ble_scan_setup(); // WiFi teardown + BLEDevice::init + getScan
    pBLEScan->setScanCallbacks(new TrackerCallbacks(), true);
    pBLEScan->setActiveScan(false);
    pBLEScan->setMaxResults(0); // callback-only, don't buffer
    pBLEScan->start(0, false);  // scan until stopped

    trackerDraw();

    while (true) {
        Sighting s;
        int drained = 0;
        while (drained++ < 32 && ringPop(s)) onSighting(s);

        // ESC: in the detail page, go back to the list; in the list, exit.
        if (check(EscPress)) {
            if (detailView) {
                detailView = false;
                fullClear = true;
            } else break;
        }
        if (check(SelPress)) {
            if (detailView) detailView = false;
            else if (!trackers.empty()) detailView = true;
            fullClear = true;
        }
        if (check(PrevPress)) {
            if (!detailView && cursor > 0) cursor--;
        }
        if (check(NextPress)) {
            if (!detailView) cursor++;
        }
        char c = checkLetterShortcutPress();
        if (c == 's' || c == 'S') {
            sortMode = (SortMode)((sortMode + 1) % 3);
            cursor = 0;
            scroll = 0;
        }

        trackerDraw();
        delay(20);
    }

    pBLEScan->stop();
    stopBLEStack();
    Serial.printf(
        "[Tracker] stopped. trackers=%u dropped=%lu\n", (unsigned)trackers.size(),
        (unsigned long)ringDropped
    );
}
