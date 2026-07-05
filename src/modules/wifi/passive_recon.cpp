#include "passive_recon.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <globals.h>

// ─────────────────────────────────────────────────────────────────────────────
// Passive (receive-only) WiFi recon. STA mode (never AP, so we never beacon) +
// promiscuous management-frame capture. The rx callback runs in the WiFi task, so
// it does the minimum: parse each frame into a compact event and push it to a
// single-producer/single-consumer ring; the main loop drains it, updates the
// models, draws, and writes SD. Deauth totals are also counted directly in the
// callback so the flood metric stays accurate even if the ring overflows.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// 2.4 GHz channels to hop across.
const uint8_t recon_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
constexpr size_t N_CHANNELS = sizeof(recon_channels);

enum EvType : uint8_t { EV_PROBE = 0, EV_DEAUTH = 1, EV_AP = 2 };

struct RecEvent {
    uint8_t type;
    uint8_t subtype;
    uint8_t ch;
    int8_t rssi;
    uint8_t src[6];
    uint8_t dst[6];
    uint8_t bssid[6];
    char ssid[33];
    uint8_t enc; // EV_AP only
    uint8_t pmf; // EV_AP only: 0 none, 1 capable, 2 required
    uint16_t reason; // EV_DEAUTH only
};

// Ring buffer (callback = producer, loop = consumer).
constexpr size_t RING_SZ = 128;
RecEvent ring[RING_SZ];
volatile uint16_t ringHead = 0;
volatile uint16_t ringTail = 0;
volatile uint32_t ringDropped = 0;

// Direct-from-callback counters (accurate under ring overflow).
volatile uint32_t cbFrames = 0;
volatile uint32_t cbProbe = 0;
volatile uint32_t cbDeauth = 0;
volatile uint32_t cbBeacon = 0;

void ringPush(const RecEvent &e) {
    uint16_t next = (ringHead + 1) % RING_SZ;
    if (next == ringTail) {
        ringDropped = ringDropped + 1;
        return;
    }
    ring[ringHead] = e;
    ringHead = next;
}

bool ringPop(RecEvent &e) {
    if (ringTail == ringHead) return false;
    e = ring[ringTail];
    ringTail = (ringTail + 1) % RING_SZ;
    return true;
}

// Copy the SSID (tag 0) from the tagged parameters starting at `off` into out[33].
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

// Determine encryption + PMF from a beacon/probe-response body. `off` is the start
// of the tagged parameters (36 for beacon/probe-resp). Capability info is the two
// bytes just before it (privacy bit). RSN (tag 48) carries the PMF bits.
void parseSecurity(const uint8_t *p, int len, int off, uint8_t &enc, uint8_t &pmf) {
    enc = 0;
    pmf = 0;
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
        if (tag == 48 && tl >= 8) { // RSN Information Element
            rsn = true;
            int q = 2 + 4; // version(2) + group cipher suite(4)
            if (q + 2 <= tl) {
                uint16_t pw = d[q] | (d[q + 1] << 8);
                q += 2 + 4 * pw; // pairwise count + suites
                if (q + 2 <= tl) {
                    uint16_t akm = d[q] | (d[q + 1] << 8);
                    int a = q + 2;
                    for (uint16_t i = 0; i < akm && a + 4 <= tl; i++) {
                        uint8_t t = d[a + 3]; // AKM suite type (last byte of the 4-byte OUI+type)
                        if (t == 8 || t == 9) sae = true; // SAE / FT-SAE -> WPA3
                        a += 4;
                    }
                    q += 2 + 4 * akm;
                    if (q + 2 <= tl) {
                        uint16_t caps = d[q] | (d[q + 1] << 8);
                        if (caps & 0x0040) pmf = 2;      // MFPR (required)
                        else if (caps & 0x0080) pmf = 1; // MFPC (capable)
                    }
                }
            }
        } else if (tag == 221 && tl >= 4 && d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01) {
            wpa = true; // Microsoft WPA IE
        }
        o += 2 + tl;
    }
    if (sae) enc = 4;         // WPA3
    else if (rsn) enc = 3;    // WPA2
    else if (wpa) enc = 2;    // WPA
    else if (privacy) enc = 1; // WEP
    else enc = 0;             // OPEN
}

void recon_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint8_t fc0 = p[0];
    if (((fc0 >> 2) & 0x03) != 0) return; // management frames only
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    cbFrames = cbFrames + 1;

    RecEvent e = {};
    e.subtype = subtype;
    e.ch = pkt->rx_ctrl.channel;
    e.rssi = pkt->rx_ctrl.rssi;
    memcpy(e.dst, p + 4, 6);
    memcpy(e.src, p + 10, 6);
    memcpy(e.bssid, p + 16, 6);

    if (subtype == 0x04) { // probe request
        e.type = EV_PROBE;
        extractSsid(p, len, 24, e.ssid); // no fixed params before tags
        cbProbe = cbProbe + 1;
    } else if (subtype == 0x0C || subtype == 0x0A) { // deauth / disassoc
        e.type = EV_DEAUTH;
        if (len >= 26) e.reason = p[24] | (p[25] << 8);
        cbDeauth = cbDeauth + 1;
    } else if (subtype == 0x08 || subtype == 0x05) { // beacon / probe response
        e.type = EV_AP;
        extractSsid(p, len, 36, e.ssid);
        parseSecurity(p, len, 36, e.enc, e.pmf);
        cbBeacon = cbBeacon + 1;
    } else {
        return; // ignore auth/assoc/action
    }
    ringPush(e);
}

// ── Models ──────────────────────────────────────────────────────────────────
struct ProbeEnt {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint16_t count;
    uint32_t lastMs;
};
struct ApEnt {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t ch;
    int8_t rssi;
    uint8_t enc;
    uint8_t pmf;
    uint16_t count;
    uint32_t lastMs;
};
struct SrcEnt {
    uint8_t mac[6];
    uint32_t count;
};

constexpr size_t PROBE_MAX = 96;
constexpr size_t AP_MAX = 96;
constexpr size_t SRC_MAX = 24;
std::vector<ProbeEnt> probes;
std::vector<ApEnt> aps;
std::vector<SrcEnt> deauthSrcs; // top talkers for the deauth view
uint16_t lastDeauthReason = 0;

enum View : uint8_t { V_PROBES = 0, V_DEAUTH = 1, V_APS = 2 };
View view = V_PROBES;
int scroll = 0;

// Channel hop state.
size_t chIdx = 0;
bool chLocked = false;
uint32_t lastHopMs = 0;
constexpr uint32_t HOP_MS = 300;

// Deauth rate (frames/sec), for the flood alarm.
uint32_t deauthRate = 0;
uint32_t lastRateCalcMs = 0;
uint32_t lastDeauthCount = 0;
constexpr uint32_t DEAUTH_ALERT_RATE = 10; // frames/sec that counts as a flood

// ── SD logging (best-effort) ───────────────────────────────────────────────
bool reconSd = false;
const char *RECON_DIR = "/BruceRecon";
const char *PROBE_CSV = "/BruceRecon/probes.csv";
const char *DEAUTH_CSV = "/BruceRecon/deauth.csv";
const char *AP_CSV = "/BruceRecon/aps.csv";

String macStr(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
}
const char *encName(uint8_t e) {
    switch (e) {
    case 0: return "OPEN";
    case 1: return "WEP";
    case 2: return "WPA";
    case 3: return "WPA2";
    case 4: return "WPA3";
    default: return "?";
    }
}
const char *pmfName(uint8_t p) { return p == 2 ? "REQ" : p == 1 ? "cap" : "-"; }

void logLine(const char *path, const String &line) {
    if (!reconSd) return;
    File f = SD.open(path, FILE_APPEND);
    if (!f) return;
    f.println(line);
    f.close();
}

// ── Model updates (main loop only) ──────────────────────────────────────────
bool sameMac(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

void onProbe(const RecEvent &e) {
    for (auto &pr : probes) {
        if (sameMac(pr.mac, e.src) && strcmp(pr.ssid, e.ssid) == 0) {
            pr.rssi = e.rssi;
            pr.lastMs = millis();
            if (pr.count < 0xFFFF) pr.count++;
            return;
        }
    }
    if (probes.size() >= PROBE_MAX) probes.erase(probes.begin());
    ProbeEnt pr = {};
    memcpy(pr.mac, e.src, 6);
    strlcpy(pr.ssid, e.ssid, sizeof(pr.ssid));
    pr.rssi = e.rssi;
    pr.count = 1;
    pr.lastMs = millis();
    probes.push_back(pr);
    // First-seen (mac,ssid) pair -> the client's PNL entry, logged once.
    logLine(
        PROBE_CSV,
        String(millis()) + "," + macStr(e.src) + ",\"" + String(e.ssid) + "\"," + String(e.rssi) + "," +
            String(e.ch)
    );
}

void onAp(const RecEvent &e) {
    for (auto &ap : aps) {
        if (sameMac(ap.bssid, e.bssid)) {
            ap.rssi = e.rssi;
            ap.ch = e.ch;
            ap.pmf = e.pmf;
            ap.enc = e.enc;
            ap.lastMs = millis();
            if (ap.count < 0xFFFF) ap.count++;
            if (ap.ssid[0] == 0 && e.ssid[0]) strlcpy(ap.ssid, e.ssid, sizeof(ap.ssid));
            return;
        }
    }
    if (aps.size() >= AP_MAX) aps.erase(aps.begin());
    ApEnt ap = {};
    memcpy(ap.bssid, e.bssid, 6);
    strlcpy(ap.ssid, e.ssid, sizeof(ap.ssid));
    ap.ch = e.ch;
    ap.rssi = e.rssi;
    ap.enc = e.enc;
    ap.pmf = e.pmf;
    ap.count = 1;
    ap.lastMs = millis();
    aps.push_back(ap);
    logLine(
        AP_CSV,
        String(millis()) + "," + macStr(e.bssid) + ",\"" + String(e.ssid) + "\"," + String(e.ch) + "," +
            encName(e.enc) + "," + pmfName(e.pmf) + "," + String(e.rssi)
    );
}

void onDeauth(const RecEvent &e) {
    lastDeauthReason = e.reason;
    for (auto &s : deauthSrcs) {
        if (sameMac(s.mac, e.src)) {
            s.count++;
            goto logged;
        }
    }
    if (deauthSrcs.size() < SRC_MAX) {
        SrcEnt s = {};
        memcpy(s.mac, e.src, 6);
        s.count = 1;
        deauthSrcs.push_back(s);
    }
logged:
    logLine(
        DEAUTH_CSV,
        String(millis()) + "," + String(e.ch) + "," + (e.subtype == 0x0C ? "deauth" : "disassoc") + "," +
            macStr(e.src) + "," + macStr(e.dst) + "," + macStr(e.bssid) + "," + String(e.reason)
    );
}

// ── Rendering (per-row diffed, no periodic full clears -> no flicker) ────────
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

void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(
        l0, sizeof(l0), "Passive Recon  CH%02u%s  drop:%lu", recon_channels[chIdx],
        chLocked ? "[L]" : "   ", (unsigned long)ringDropped
    );
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }

    char l1[80];
    uint16_t fg = TFT_GREEN;
    if (view == V_PROBES) {
        snprintf(
            l1, sizeof(l1), "PROBES  clients:%u  frames:%lu", (unsigned)probes.size(),
            (unsigned long)cbProbe
        );
    } else if (view == V_DEAUTH) {
        bool alert = deauthRate >= DEAUTH_ALERT_RATE;
        snprintf(
            l1, sizeof(l1), "DEAUTH  total:%lu  rate:%lu/s%s", (unsigned long)cbDeauth,
            (unsigned long)deauthRate, alert ? "  ** FLOOD **" : ""
        );
        fg = alert ? TFT_RED : (cbDeauth ? TFT_YELLOW : TFT_GREEN);
    } else {
        snprintf(l1, sizeof(l1), "APs:%u  (enc / PMF)", (unsigned)aps.size());
    }
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(fg, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}

void drawFooter() {
    String hint = "SEL view  ^v scroll  l lock  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

// Build display-ordered indices (most-recently-seen first) for probes/aps.
template <typename T> void sortRecent(const std::vector<T> &v, std::vector<int> &idx) {
    idx.resize(v.size());
    for (size_t i = 0; i < v.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) { return v[a].lastMs > v[b].lastMs; });
}

void drawBody() {
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;

    // Collect the rows to show as strings first, so scrolling/blanking is uniform.
    std::vector<String> lines;
    std::vector<uint16_t> fgs;

    if (view == V_PROBES) {
        std::vector<int> idx;
        sortRecent(probes, idx);
        for (int i : idx) {
            const ProbeEnt &pr = probes[i];
            String ssid = pr.ssid[0] ? String(pr.ssid) : String("<broadcast>");
            if (ssid.length() > 20) ssid = ssid.substring(0, 20);
            lines.push_back(macStr(pr.mac) + " " + ssid + " " + String(pr.rssi) + " x" + String(pr.count));
            fgs.push_back(pr.ssid[0] ? TFT_WHITE : TFT_DARKGREY);
        }
    } else if (view == V_APS) {
        std::vector<int> idx;
        sortRecent(aps, idx);
        for (int i : idx) {
            const ApEnt &ap = aps[i];
            String ssid = ap.ssid[0] ? String(ap.ssid) : String("<hidden>");
            if (ssid.length() > 16) ssid = ssid.substring(0, 16);
            char tail[32];
            snprintf(tail, sizeof(tail), " %-4s %-3s %d", encName(ap.enc), pmfName(ap.pmf), ap.rssi);
            lines.push_back("c" + String(ap.ch) + " " + ssid + tail);
            // Highlight PMF-required APs (deauth-immune) in cyan.
            fgs.push_back(ap.pmf == 2 ? TFT_CYAN : TFT_WHITE);
        }
    } else { // V_DEAUTH
        if (deauthSrcs.empty()) {
            lines.push_back("no deauth/disassoc seen yet");
            fgs.push_back(TFT_DARKGREY);
        } else {
            lines.push_back("last reason code: " + String(lastDeauthReason));
            fgs.push_back(TFT_DARKGREY);
            std::vector<int> idx(deauthSrcs.size());
            for (size_t i = 0; i < deauthSrcs.size(); i++) idx[i] = (int)i;
            std::sort(idx.begin(), idx.end(), [&](int a, int b) {
                return deauthSrcs[a].count > deauthSrcs[b].count;
            });
            for (int i : idx) {
                lines.push_back(macStr(deauthSrcs[i].mac) + "  x" + String(deauthSrcs[i].count));
                fgs.push_back(TFT_YELLOW);
            }
        }
    }

    int total = (int)lines.size();
    int maxScroll = total - rows;
    if (maxScroll < 0) maxScroll = 0;
    if (scroll > maxScroll) scroll = maxScroll;
    if (scroll < 0) scroll = 0;

    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int i = scroll + slot;
        if (i < total) drawRow(slot, y, lines[i], fgs[i]);
        else drawRow(slot, y, "", TFT_WHITE);
    }
}

void reconDraw() {
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
    esp_wifi_set_channel(recon_channels[chIdx], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
}

} // namespace

void passive_recon() {
    Serial.println("[Recon] passive WiFi recon starting (RX-only)");
    probes.clear();
    aps.clear();
    deauthSrcs.clear();
    ringHead = 0;
    ringTail = 0;
    ringDropped = 0;
    cbFrames = 0;
    cbProbe = 0;
    cbDeauth = 0;
    cbBeacon = 0;
    lastDeauthCount = deauthRate = 0;
    view = V_PROBES;
    scroll = 0;
    chIdx = 0;
    chLocked = false;
    fullClear = true;

    // SD logging (best-effort). Write CSV headers on first create.
    reconSd = false;
    if (sdcardMounted || setupSdCard()) {
        if (!SD.exists(RECON_DIR)) SD.mkdir(RECON_DIR);
        reconSd = true;
        if (!SD.exists(PROBE_CSV)) logLine(PROBE_CSV, "uptime_ms,mac,ssid,rssi,channel");
        if (!SD.exists(DEAUTH_CSV)) logLine(DEAUTH_CSV, "uptime_ms,channel,type,src,dst,bssid,reason");
        if (!SD.exists(AP_CSV)) logLine(AP_CSV, "uptime_ms,bssid,ssid,channel,enc,pmf,rssi");
        Serial.println("[Recon] SD logging -> /BruceRecon/{probes,deauth,aps}.csv");
    } else {
        Serial.println("[Recon] no SD card - logging disabled");
    }

    // Promiscuous RX in STA mode. STA (not AP) means we never transmit a beacon;
    // an idle unconnected STA sends nothing, so this stays purely passive.
    wifi_mode_t prevMode = WiFi.getMode();
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(recon_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(recon_channels[chIdx], WIFI_SECOND_CHAN_NONE);

    reconDraw();
    lastHopMs = lastRateCalcMs = millis();

    while (!check(EscPress)) {
        // Drain captured events into the models.
        RecEvent e;
        int drained = 0;
        while (drained++ < 64 && ringPop(e)) {
            if (e.type == EV_PROBE) onProbe(e);
            else if (e.type == EV_AP) onAp(e);
            else if (e.type == EV_DEAUTH) onDeauth(e);
        }

        // Channel hop.
        if (!chLocked && millis() - lastHopMs > HOP_MS) {
            lastHopMs = millis();
            hopChannel();
        }

        // Deauth rate once per second (uses the callback counter, overflow-proof).
        if (millis() - lastRateCalcMs >= 1000) {
            uint32_t now = millis();
            uint32_t dt = now - lastRateCalcMs;
            deauthRate = (cbDeauth - lastDeauthCount) * 1000UL / (dt ? dt : 1000);
            lastDeauthCount = cbDeauth;
            lastRateCalcMs = now;
        }

        // Input.
        if (check(SelPress)) {
            view = (View)((view + 1) % 3);
            scroll = 0;
            fullClear = true;
        }
        if (check(PrevPress) && scroll > 0) scroll--;
        if (check(NextPress)) scroll++;
        char c = checkLetterShortcutPress();
        if (c == 'l' || c == 'L') chLocked = !chLocked;

        reconDraw();
        delay(15);
    }

    // Teardown: stop promiscuous, restore the previous WiFi mode.
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevMode);
    Serial.printf(
        "[Recon] stopped. probes=%u aps=%u deauth=%lu dropped=%lu\n", (unsigned)probes.size(),
        (unsigned)aps.size(), (unsigned long)cbDeauth, (unsigned long)ringDropped
    );
}
