#include "rogue_ap.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive rogue-AP / Karma detector on the same promiscuous capture core as
// passive_recon.cpp (STA + MGMT capture, channel-hopping; never transmits).
// Heuristics, all receive-only:
//   - KARMA:     one BSSID that beacons / probe-responds for MANY distinct SSIDs
//                over the session (a Karma/"answer any probe" rig).
//   - EVIL TWIN: the same SSID advertised by two or more different BSSIDs.
//   - DEAUTH:    a source flooding deauth/disassoc frames (jammer / MITM kick).
// Suspicious APs are shown with a reason code + RSSI, mirrored to serial and
// logged to SD. WiFi mode restored on exit.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

const uint8_t rogue_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
constexpr size_t N_CHANNELS = sizeof(rogue_channels);

constexpr uint16_t KARMA_THRESH = 4;      // distinct SSIDs from one BSSID -> Karma
constexpr uint32_t DEAUTH_SRC_THRESH = 8; // deauth frames from one src -> flag
constexpr uint32_t DEAUTH_ALERT_RATE = 10;

constexpr uint8_t R_KARMA = 0x01;
constexpr uint8_t R_EVILTWIN = 0x02;
constexpr uint8_t R_DEAUTH = 0x04;

// ── Capture event (callback -> ring) ─────────────────────────────────────────
enum EvType : uint8_t { EV_AP = 0, EV_DEAUTH = 1 };
struct RogueEvent {
    uint8_t type;
    uint8_t ch;
    int8_t rssi;
    uint8_t bssid[6]; // AP: bssid; DEAUTH: src
    char ssid[33];
    uint8_t enc;
};

constexpr size_t RING_SZ = 128;
RogueEvent ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;
volatile uint32_t cbDeauth = 0;

void ringPush(const RogueEvent &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}
bool ringPop(RogueEvent &e) {
    if (ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

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

// Compact encryption detection (privacy bit + RSN/WPA IE presence).
uint8_t parseEnc(const uint8_t *p, int len, int off) {
    bool privacy = false;
    if (off >= 2 && off <= len) {
        uint16_t cap = p[off - 2] | (p[off - 1] << 8);
        privacy = cap & 0x0010;
    }
    bool rsn = false, wpa = false, sae = false;
    int o = off;
    while (o + 2 <= len) {
        uint8_t tag = p[o];
        uint8_t tl = p[o + 1];
        if (o + 2 + tl > len) break;
        const uint8_t *d = p + o + 2;
        if (tag == 48) rsn = true;
        else if (tag == 221 && tl >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01)
            wpa = true;
        o += 2 + tl;
    }
    (void)sae;
    if (rsn) return 3;      // WPA2/3
    if (wpa) return 2;      // WPA
    if (privacy) return 1;  // WEP
    return 0;               // OPEN
}
const char *encName(uint8_t e) {
    return e == 3 ? "WPA2" : e == 2 ? "WPA" : e == 1 ? "WEP" : "OPEN";
}

void rogue_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;
    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 0) return; // management only
    uint8_t subtype = (fc0 >> 4) & 0x0F;

    RogueEvent e = {};
    e.ch = pkt->rx_ctrl.channel;
    e.rssi = pkt->rx_ctrl.rssi;

    if (subtype == 0x08 || subtype == 0x05) { // beacon / probe response
        e.type = EV_AP;
        memcpy(e.bssid, p + 16, 6);
        extractSsid(p, len, 36, e.ssid);
        e.enc = parseEnc(p, len, 36);
        if (e.ssid[0] == 0) return; // ignore hidden/wildcard for the SSID heuristics
    } else if (subtype == 0x0C || subtype == 0x0A) { // deauth / disassoc
        e.type = EV_DEAUTH;
        memcpy(e.bssid, p + 10, 6); // source
        cbDeauth = cbDeauth + 1;
    } else return;
    ringPush(e);
}

// ── Models (main loop) ───────────────────────────────────────────────────────
constexpr uint8_t SSID_SAMPLES = 8;
struct ApRec {
    uint8_t bssid[6];
    char ssids[SSID_SAMPLES][33]; // sample of distinct SSIDs seen
    uint8_t nSamples;
    uint16_t distinctSsids; // true distinct count (may exceed samples)
    int8_t rssi, bestRssi;
    uint8_t ch;
    uint8_t enc;
    uint16_t count;
    uint32_t firstMs, lastMs;
    uint8_t reason; // recomputed each analysis pass
};
struct DeauthSrc {
    uint8_t mac[6];
    uint32_t count;
    uint8_t ch;
    int8_t rssi;
};
constexpr size_t AP_MAX = 128;
constexpr size_t DEAUTH_MAX = 32;
std::vector<ApRec> aps;
std::vector<DeauthSrc> deauthSrcs;

int scroll = 0;
int cursor = 0;          // selected row (index into the unified display order)
bool detailView = false; // showing the per-row detail page for `cursor`

// A selectable row in the unified list: a flagged AP or a standalone deauth src.
enum RowKind : uint8_t { ROW_AP = 0, ROW_DEAUTH = 1 };
struct RogueRow {
    uint8_t kind;
    int idx; // index into aps[] (ROW_AP) or deauthSrcs[] (ROW_DEAUTH)
};

size_t chIdx = 0;
bool chLocked = false;
uint32_t lastHopMs = 0;
constexpr uint32_t HOP_MS = 300;

uint32_t deauthRate = 0, lastRateMs = 0, lastDeauthCount = 0;

bool sameMac(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

String macStr(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
}

// ── SD logging ───────────────────────────────────────────────────────────────
bool rogueSd = false;
const char *DET_DIR = "/BruceDetector";
const char *ROGUE_CSV = "/BruceDetector/rogue_ap.csv";
String reasonStr(uint8_t r) {
    String s;
    if (r & R_KARMA) s += "KARMA ";
    if (r & R_EVILTWIN) s += "EVILTWIN ";
    if (r & R_DEAUTH) s += "DEAUTH ";
    s.trim();
    return s.length() ? s : String("-");
}
void logFlag(const char *kind, const uint8_t *mac, const String &detail, int8_t rssi, uint8_t ch) {
    if (!rogueSd) return;
    File f = SD.open(ROGUE_CSV, FILE_APPEND);
    if (!f) return;
    f.println(
        String(millis()) + "," + kind + "," + macStr(mac) + ",\"" + detail + "\"," + String(rssi) + "," +
        String(ch)
    );
    f.close();
}

void onAp(const RogueEvent &e) {
    for (auto &ap : aps) {
        if (sameMac(ap.bssid, e.bssid)) {
            ap.rssi = e.rssi;
            if (e.rssi > ap.bestRssi) ap.bestRssi = e.rssi;
            ap.ch = e.ch;
            ap.enc = e.enc;
            ap.lastMs = millis();
            if (ap.count < 0xFFFF) ap.count++;
            // Track distinct SSIDs from this BSSID (the Karma signal).
            bool known = false;
            for (uint8_t i = 0; i < ap.nSamples; i++)
                if (strcmp(ap.ssids[i], e.ssid) == 0) {
                    known = true;
                    break;
                }
            if (!known) {
                ap.distinctSsids++;
                if (ap.nSamples < SSID_SAMPLES) strlcpy(ap.ssids[ap.nSamples++], e.ssid, 33);
            }
            return;
        }
    }
    if (aps.size() >= AP_MAX) aps.erase(aps.begin());
    ApRec ap = {};
    memcpy(ap.bssid, e.bssid, 6);
    strlcpy(ap.ssids[0], e.ssid, 33);
    ap.nSamples = 1;
    ap.distinctSsids = 1;
    ap.rssi = ap.bestRssi = e.rssi;
    ap.ch = e.ch;
    ap.enc = e.enc;
    ap.count = 1;
    ap.firstMs = ap.lastMs = millis();
    aps.push_back(ap);
}

void onDeauth(const RogueEvent &e) {
    for (auto &s : deauthSrcs) {
        if (sameMac(s.mac, e.bssid)) {
            s.count++;
            s.ch = e.ch;
            s.rssi = e.rssi;
            return;
        }
    }
    if (deauthSrcs.size() < DEAUTH_MAX) {
        DeauthSrc s = {};
        memcpy(s.mac, e.bssid, 6);
        s.count = 1;
        s.ch = e.ch;
        s.rssi = e.rssi;
        deauthSrcs.push_back(s);
    }
}

// Recompute reason flags across all APs. Returns number of flagged APs.
int analyze() {
    // Evil twin: build per-SSID BSSID presence. For each AP sample SSID, if any
    // OTHER AP advertises the same SSID, both are evil-twin candidates.
    for (auto &ap : aps) {
        ap.reason = 0;
        if (ap.distinctSsids >= KARMA_THRESH) ap.reason |= R_KARMA;
    }
    for (size_t i = 0; i < aps.size(); i++) {
        for (size_t j = i + 1; j < aps.size(); j++) {
            if (sameMac(aps[i].bssid, aps[j].bssid)) continue;
            bool shared = false;
            for (uint8_t a = 0; a < aps[i].nSamples && !shared; a++)
                for (uint8_t b = 0; b < aps[j].nSamples; b++)
                    if (aps[i].ssids[a][0] && strcmp(aps[i].ssids[a], aps[j].ssids[b]) == 0) {
                        shared = true;
                        break;
                    }
            if (shared) {
                aps[i].reason |= R_EVILTWIN;
                aps[j].reason |= R_EVILTWIN;
            }
        }
    }
    // Deauth: mark APs whose BSSID is a heavy deauth source.
    for (auto &s : deauthSrcs) {
        if (s.count < DEAUTH_SRC_THRESH) continue;
        for (auto &ap : aps)
            if (sameMac(ap.bssid, s.mac)) ap.reason |= R_DEAUTH;
    }
    int flagged = 0;
    for (auto &ap : aps)
        if (ap.reason) flagged++;
    return flagged;
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

int lastFlagged = 0;

void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(
        l0, sizeof(l0), "Rogue AP  CH%02u%s  drop:%lu", rogue_channels[chIdx], chLocked ? "[L]" : "   ",
        (unsigned long)ringDropped
    );
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    bool flood = deauthRate >= DEAUTH_ALERT_RATE;
    char l1[72];
    snprintf(
        l1, sizeof(l1), "aps:%u flagged:%d deauth:%lu/s%s", (unsigned)aps.size(), lastFlagged,
        (unsigned long)deauthRate, flood ? " FLOOD" : ""
    );
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        uint16_t fg = (lastFlagged > 0 || flood) ? TFT_RED : TFT_GREEN;
        tft.setTextColor(fg, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter() {
    String hint = detailView ? "<-/SEL back  ^v scroll" : "SEL details  ^v select  l lock  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

String fmtSpan(uint32_t ms) {
    uint32_t s = ms / 1000;
    if (s < 60) return String(s) + "s";
    if (s < 3600) return String(s / 60) + "m" + String(s % 60) + "s";
    return String(s / 3600) + "h" + String((s % 3600) / 60) + "m";
}

// Build the unified selectable list: flagged APs (reason != 0) sorted by signal,
// then heavy deauth sources not already covered by a flagged AP. Shared by the
// table and the detail page so `cursor` maps to the same record in both.
void buildRogueList(std::vector<RogueRow> &out) {
    out.clear();
    std::vector<int> idx;
    for (size_t i = 0; i < aps.size(); i++)
        if (aps[i].reason) idx.push_back((int)i);
    std::sort(idx.begin(), idx.end(), [&](int a, int b) { return aps[a].bestRssi > aps[b].bestRssi; });
    for (int i : idx) out.push_back({ROW_AP, i});
    for (size_t si = 0; si < deauthSrcs.size(); si++) {
        if (deauthSrcs[si].count < DEAUTH_SRC_THRESH) continue;
        bool isAp = false;
        for (auto &ap : aps)
            if (sameMac(ap.bssid, deauthSrcs[si].mac) && ap.reason) {
                isAp = true;
                break;
            }
        if (isAp) continue;
        out.push_back({ROW_DEAUTH, (int)si});
    }
}

void drawBody() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    std::vector<RogueRow> list;
    buildRogueList(list);
    int total = (int)list.size();
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
                drawRow(slot, y, "  (no rogue signatures yet)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        char sel = (li == cursor) ? '>' : ' ';
        if (list[li].kind == ROW_AP) {
            const ApRec &ap = aps[list[li].idx];
            String ssid = ap.ssids[0][0] ? String(ap.ssids[0]) : String("<?>");
            if (ssid.length() > 11) ssid = ssid.substring(0, 11);
            String rc;
            if (ap.reason & R_KARMA) rc += "K";
            if (ap.reason & R_EVILTWIN) rc += "E";
            if (ap.reason & R_DEAUTH) rc += "D";
            String extra = (ap.reason & R_KARMA) ? (" #" + String(ap.distinctSsids)) : "";
            String line = String(sel) + rc + " " + ssid + extra + " c" + String(ap.ch) + " " +
                          String(ap.rssi) + " " + macStr(ap.bssid).substring(9);
            drawRow(slot, y, line, li == cursor ? TFT_CYAN : TFT_RED);
        } else {
            const DeauthSrc &s = deauthSrcs[list[li].idx];
            String line = String(sel) + "D deauth " + macStr(s.mac).substring(9) + " x" + String(s.count);
            drawRow(slot, y, line, li == cursor ? TFT_CYAN : TFT_YELLOW);
        }
    }
}

// Per-row detail page: full MAC/BSSID and a plain-language breakdown of *why*
// the row was flagged (which heuristic(s) fired and the evidence behind each).
void drawDetail() {
    std::vector<RogueRow> list;
    buildRogueList(list);
    if (list.empty()) {
        drawRow(0, CHROME_H, "  (nothing selected)", TFT_DARKGREY);
        for (int s = 1; s < MAX_ROWS; s++) drawRow(s, CHROME_H + s * ROW_H, "", TFT_WHITE);
        return;
    }
    if (cursor >= (int)list.size()) cursor = list.size() - 1;
    if (cursor < 0) cursor = 0;

    String lines[MAX_ROWS];
    uint16_t fgs[MAX_ROWS];
    for (int i = 0; i < MAX_ROWS; i++) { lines[i] = ""; fgs[i] = TFT_WHITE; }
    int n = 0;
    uint32_t now = millis();

    if (list[cursor].kind == ROW_AP) {
        const ApRec &ap = aps[list[cursor].idx];
        lines[n] = String("BSSID: ") + macStr(ap.bssid); fgs[n++] = TFT_WHITE;
        lines[n] = String("SSID: ") + (ap.ssids[0][0] ? String(ap.ssids[0]) : String("<hidden>"));
        fgs[n++] = TFT_CYAN;
        lines[n] = String("Ch ") + ap.ch + "  enc " + encName(ap.enc) + "  x" + String(ap.count);
        fgs[n++] = TFT_WHITE;
        lines[n] = String("RSSI ") + ap.rssi + " (best " + ap.bestRssi + ")  " + fmtSpan(now - ap.lastMs) + " ago";
        fgs[n++] = TFT_WHITE;
        lines[n] = String("Distinct SSIDs: ") + ap.distinctSsids; fgs[n++] = TFT_WHITE;
        lines[n] = String("Reason: ") + reasonStr(ap.reason); fgs[n++] = TFT_RED;
        lines[n] = ""; fgs[n++] = TFT_WHITE;
        lines[n] = "Why flagged:"; fgs[n++] = bruceConfig.priColor;
        if (ap.reason & R_KARMA) {
            lines[n] = String("- KARMA: answers ") + ap.distinctSsids + " SSIDs"; fgs[n++] = TFT_WHITE;
            lines[n] = String("  (>= ") + KARMA_THRESH + " from one BSSID)"; fgs[n++] = TFT_WHITE;
        }
        if (ap.reason & R_EVILTWIN) {
            lines[n] = "- EVIL TWIN: same SSID also on"; fgs[n++] = TFT_WHITE;
            lines[n] = "  a different BSSID"; fgs[n++] = TFT_WHITE;
        }
        if (ap.reason & R_DEAUTH) {
            lines[n] = "- DEAUTH: this BSSID floods"; fgs[n++] = TFT_WHITE;
            lines[n] = "  deauth/disassoc frames"; fgs[n++] = TFT_WHITE;
        }
        // Show the sampled SSIDs behind a Karma flag (the evidence).
        if ((ap.reason & R_KARMA) && ap.nSamples > 0 && n < MAX_ROWS - 1) {
            String s = "SSIDs: ";
            for (uint8_t i = 0; i < ap.nSamples && s.length() < 34; i++) {
                if (i) s += ",";
                s += ap.ssids[i];
            }
            lines[n] = s; fgs[n++] = TFT_DARKGREY;
        }
    } else {
        const DeauthSrc &s = deauthSrcs[list[cursor].idx];
        lines[n] = String("Deauth source"); fgs[n++] = TFT_YELLOW;
        lines[n] = String("MAC: ") + macStr(s.mac); fgs[n++] = TFT_WHITE;
        lines[n] = String("Ch ") + s.ch + "  RSSI " + s.rssi; fgs[n++] = TFT_WHITE;
        lines[n] = String("Deauth frames: ") + s.count; fgs[n++] = TFT_WHITE;
        lines[n] = ""; fgs[n++] = TFT_WHITE;
        lines[n] = "Why flagged:"; fgs[n++] = bruceConfig.priColor;
        lines[n] = String("- >= ") + DEAUTH_SRC_THRESH + " deauth frames from"; fgs[n++] = TFT_WHITE;
        lines[n] = "  one source (jammer / MITM"; fgs[n++] = TFT_WHITE;
        lines[n] = "  kick to force reconnect)"; fgs[n++] = TFT_WHITE;
    }

    for (int slot = 0; slot < MAX_ROWS; slot++)
        drawRow(slot, CHROME_H + slot * ROW_H, lines[slot], fgs[slot]);
}

void rogueDraw() {
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
    esp_wifi_set_channel(rogue_channels[chIdx], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

void dumpSerial() {
    Serial.printf("[RogueAP] %d flagged AP(s):\n", lastFlagged);
    for (auto &ap : aps) {
        if (!ap.reason) continue;
        Serial.printf(
            "  %s  %-16s  ch%u rssi=%d  ssids=%u  reason=%s\n", macStr(ap.bssid).c_str(),
            ap.ssids[0][0] ? ap.ssids[0] : "<?>", ap.ch, ap.rssi, ap.distinctSsids,
            reasonStr(ap.reason).c_str()
        );
    }
}

} // namespace

void rogue_ap() {
    Serial.println("[RogueAP] passive rogue-AP / Karma detector starting (RX-only)");
    aps.clear();
    deauthSrcs.clear();
    ringHead = ringTail = ringDropped = 0;
    cbDeauth = 0;
    lastDeauthCount = deauthRate = 0;
    scroll = 0;
    cursor = 0;
    detailView = false;
    chIdx = 0;
    chLocked = false;
    fullClear = true;
    lastFlagged = 0;

    rogueSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(DET_DIR)) SD.mkdir(DET_DIR);
        rogueSd = true;
        if (!SD.exists(ROGUE_CSV)) {
            File f = SD.open(ROGUE_CSV, FILE_APPEND);
            if (f) {
                f.println("uptime_ms,kind,mac,detail,rssi,channel");
                f.close();
            }
        }
        Serial.printf("[RogueAP] logging -> %s\n", ROGUE_CSV);
    } else {
        Serial.println("[RogueAP] no SD card - logging disabled");
    }

    wifi_mode_t prevMode = WiFi.getMode();
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(rogue_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(rogue_channels[chIdx], WIFI_SECOND_CHAN_NONE);

    rogueDraw();
    lastHopMs = lastRateMs = millis();
    uint8_t prevFlagged = 0;

    while (true) {
        RogueEvent e;
        int drained = 0;
        while (drained++ < 64 && ringPop(e)) {
            if (e.type == EV_AP) onAp(e);
            else onDeauth(e);
        }

        lastFlagged = analyze();
        // Log newly-crossed flags (edge-triggered on total flagged count).
        if (lastFlagged != prevFlagged) {
            for (auto &ap : aps)
                if (ap.reason)
                    logFlag("AP", ap.bssid, String(ap.ssids[0]) + " " + reasonStr(ap.reason), ap.rssi, ap.ch);
            prevFlagged = lastFlagged;
        }

        if (!chLocked && millis() - lastHopMs > HOP_MS) {
            lastHopMs = millis();
            hopChannel();
        }
        if (millis() - lastRateMs >= 1000) {
            uint32_t now = millis();
            uint32_t dt = now - lastRateMs;
            deauthRate = (cbDeauth - lastDeauthCount) * 1000UL / (dt ? dt : 1000);
            lastDeauthCount = cbDeauth;
            lastRateMs = now;
        }

        // ESC: in the detail page, go back to the list; in the list, exit.
        if (check(EscPress)) {
            if (detailView) {
                detailView = false;
                fullClear = true;
            } else break;
        }
        if (check(SelPress)) {
            std::vector<RogueRow> list;
            buildRogueList(list);
            if (detailView) detailView = false;
            else if (!list.empty()) detailView = true;
            fullClear = true;
        }
        if (check(PrevPress)) {
            if (!detailView && cursor > 0) cursor--;
        }
        if (check(NextPress)) {
            if (!detailView) cursor++;
        }
        char c = checkLetterShortcutPress();
        if (c == 'l' || c == 'L') chLocked = !chLocked;
        if (Serial.available()) {
            while (Serial.available()) Serial.read();
            dumpSerial();
        }

        rogueDraw();
        delay(15);
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevMode);
    Serial.printf(
        "[RogueAP] stopped. aps=%u flagged=%d deauth=%lu dropped=%lu\n", (unsigned)aps.size(),
        lastFlagged, (unsigned long)cbDeauth, (unsigned long)ringDropped
    );
}
