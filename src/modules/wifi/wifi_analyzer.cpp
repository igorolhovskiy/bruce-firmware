#include "wifi_analyzer.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <WiFi.h>
#include <globals.h>
#include <math.h>

extern bool showHiddenNetworks; // defined in WifiMenu.cpp

// ─── Graph geometry (320x240 landscape) ──────────────────────────────────────
static const int PLOT_L = 26;  // left edge of plot (room for dBm labels)
static const int PLOT_T = 16;  // top edge (below header)
static const int PLOT_B = 210; // baseline (above channel labels)
#define PLOT_R (tftWidth - 3)

// dBm range shown on the y-axis
static const int RSSI_TOP = -30;
static const int RSSI_BOTTOM = -100;

// 2.4 GHz WiFi channels shown on the x-axis
static const int CH_MIN = 1;
static const int CH_MAX = 14;

// One AP as we need it for drawing / serial mirror
struct ApEntry {
    char ssid[33];
    int rssi;
    uint8_t channel;
    uint8_t enc; // wifi_auth_mode_t
    uint16_t color;
};

// Stable, visually distinct colours (assigned per BSSID hash)
static const uint16_t PALETTE[] = {
    TFT_RED,
    TFT_GREEN,
    TFT_CYAN,
    TFT_YELLOW,
    TFT_MAGENTA,
    TFT_ORANGE,
    TFT_SKYBLUE,
    TFT_PINK,
    TFT_GREENYELLOW,
    TFT_VIOLET,
};
static const int PALETTE_SIZE = sizeof(PALETTE) / sizeof(PALETTE[0]);

// Dim an RGB565 colour to num/den brightness (for the curve fill)
static uint16_t dim565(uint16_t c, uint8_t num, uint8_t den) {
    uint16_t r = (c >> 11) & 0x1F;
    uint16_t g = (c >> 5) & 0x3F;
    uint16_t b = c & 0x1F;
    r = r * num / den;
    g = g * num / den;
    b = b * num / den;
    return (uint16_t)((r << 11) | (g << 5) | b);
}

static const char *encStr(uint8_t enc) {
    switch (enc) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA";
        case WIFI_AUTH_WPA2_PSK: return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/2";
        case WIFI_AUTH_WPA3_PSK: return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/3";
        default: return "Enc";
    }
}

static int chanToX(int ch) {
    return PLOT_L + (int)lround((double)(ch - CH_MIN) * (PLOT_R - PLOT_L) / (CH_MAX - CH_MIN));
}

static int rssiToY(int rssi) {
    if (rssi > RSSI_TOP) rssi = RSSI_TOP;
    if (rssi < RSSI_BOTTOM) rssi = RSSI_BOTTOM;
    double frac = (double)(RSSI_TOP - rssi) / (RSSI_TOP - RSSI_BOTTOM);
    return PLOT_T + (int)lround(frac * (PLOT_B - PLOT_T));
}

// Render the whole analyzer frame into `spr` (already created, full screen).
static void renderGraph(tft_sprite &spr, std::vector<ApEntry> &aps, int highlight, bool paused) {
    const uint16_t bg = bruceConfig.bgColor;
    const uint16_t grid = 0x2965; // faint grey
    const double pxPerCh = (double)(PLOT_R - PLOT_L) / (CH_MAX - CH_MIN);
    const double sigma = pxPerCh * 1.6; // curve half-width ~1.6 channels

    spr.fillScreen(bg);
    spr.setTextSize(1);

    // ── Header ──
    spr.setTextColor(bruceConfig.priColor);
    spr.setTextDatum(TL_DATUM);
    spr.drawString("WiFi Analyzer", 2, 3);
    spr.setTextDatum(TR_DATUM);
    char hdr[32];
    snprintf(hdr, sizeof(hdr), "%d AP  %s", (int)aps.size(), paused ? "PAUSED" : "scan");
    spr.drawString(hdr, PLOT_R, 3);

    // ── Axes / grid ──
    spr.setTextColor(TFT_DARKGREY);
    spr.setTextDatum(MR_DATUM);
    for (int dbm = -40; dbm >= -90; dbm -= 10) {
        int y = rssiToY(dbm);
        spr.drawLine(PLOT_L, y, PLOT_R, y, grid);
        spr.drawString(String(dbm), PLOT_L - 2, y);
    }
    spr.drawLine(PLOT_L, PLOT_T, PLOT_L, PLOT_B, TFT_DARKGREY); // y axis
    spr.drawLine(PLOT_L, PLOT_B, PLOT_R, PLOT_B, TFT_DARKGREY); // x axis (baseline)

    // channel numbers
    spr.setTextDatum(TC_DATUM);
    for (int ch = CH_MIN; ch <= CH_MAX; ch++) {
        spr.drawString(String(ch), chanToX(ch), PLOT_B + 3);
    }

    // ── Bell curves (highlighted one drawn last, on top) ──
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < aps.size(); i++) {
            bool isHi = ((int)i == highlight);
            if ((pass == 0) == isHi) continue; // pass0: others, pass1: highlighted

            ApEntry &ap = aps[i];
            int centerX = chanToX(ap.channel);
            int peakY = rssiToY(ap.rssi);
            uint16_t fill = dim565(ap.color, isHi ? 5 : 3, 10);

            int prevX = -1, prevY = 0;
            for (int x = PLOT_L; x <= PLOT_R; x++) {
                double dx = (x - centerX);
                double frac = exp(-(dx * dx) / (2.0 * sigma * sigma));
                if (frac < 0.02) continue;
                int curveY = PLOT_B - (int)lround((PLOT_B - peakY) * frac);
                spr.drawFastVLine(x, curveY, PLOT_B - curveY, fill);
                if (prevX >= 0) spr.drawLine(prevX, prevY, x, curveY, ap.color);
                prevX = x;
                prevY = curveY;
            }

            // SSID label above the peak
            if (peakY - 2 > PLOT_T + 6) {
                spr.setTextColor(ap.color);
                spr.setTextDatum(BC_DATUM);
                const char *name = ap.ssid[0] ? ap.ssid : "<hidden>";
                spr.drawString(name, centerX, peakY - 2);
            }
        }
    }

    // ── Highlighted detail readout (footer) ──
    if (highlight >= 0 && highlight < (int)aps.size()) {
        ApEntry &ap = aps[highlight];
        char line[64];
        snprintf(
            line,
            sizeof(line),
            "%s  ch%d  %ddBm  %s",
            ap.ssid[0] ? ap.ssid : "<hidden>",
            ap.channel,
            ap.rssi,
            encStr(ap.enc)
        );
        spr.setTextColor(ap.color);
        spr.setTextDatum(BL_DATUM);
        spr.drawString(line, 2, tftHeight - 2);
    } else if (aps.empty()) {
        spr.setTextColor(TFT_DARKGREY);
        spr.setTextDatum(BL_DATUM);
        spr.drawString("No networks found - scanning...", 2, tftHeight - 2);
    }
}

static void logScan(std::vector<ApEntry> &aps) {
    Serial.printf("[WiFiAnalyzer] scan: %d networks\n", (int)aps.size());
    for (size_t i = 0; i < aps.size(); i++) {
        ApEntry &ap = aps[i];
        Serial.printf(
            "  %2d  ch%-2d  %4d dBm  %-6s  %s\n",
            (int)i,
            ap.channel,
            ap.rssi,
            encStr(ap.enc),
            ap.ssid[0] ? ap.ssid : "<hidden>"
        );
    }
}

void wifi_analyzer() {
    // Preserve and set WiFi mode for scanning; restore on exit.
    wifi_mode_t prevMode = WiFi.getMode();
    if (prevMode == WIFI_MODE_NULL) WiFi.mode(WIFI_MODE_STA);
    WiFi.scanDelete();

    tft_sprite spr(&tft);
    spr.setColorDepth(16);
    bool haveSprite = (spr.createSprite(tftWidth, tftHeight) != nullptr);
    if (!haveSprite) {
        // Fallback: still usable, just draws straight to the screen (may flicker).
        Serial.println("[WiFiAnalyzer] sprite alloc failed, drawing direct");
    }

    std::vector<ApEntry> aps;
    int highlight = -1;
    bool paused = false;
    bool dirty = true;         // needs a redraw
    bool scanRunning = false;
    unsigned long lastScanDone = 0;
    const unsigned long RESCAN_MS = 2500;

    tft.fillScreen(bruceConfig.bgColor);
    Serial.println("[WiFiAnalyzer] opened");

    auto redraw = [&]() {
        if (haveSprite) {
            renderGraph(spr, aps, highlight, paused);
            spr.pushSprite(0, 0);
        } else {
            // direct draw into a scratch use of the same routine is not possible
            // (renderGraph needs a sprite); do a minimal direct fallback.
            tft.fillScreen(bruceConfig.bgColor);
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            tft.setTextDatum(TL_DATUM);
            tft.drawString("WiFi Analyzer (no sprite)", 2, 3);
            for (size_t i = 0; i < aps.size() && i < 12; i++) {
                tft.drawString(
                    String(aps[i].channel) + " " + String(aps[i].rssi) + " " +
                        (aps[i].ssid[0] ? aps[i].ssid : "<hidden>"),
                    2,
                    16 + (int)i * 12
                );
            }
        }
    };

    while (!check(EscPress)) {
        // ── Async scan lifecycle ──
        if (!scanRunning && !paused && (millis() - lastScanDone > RESCAN_MS || lastScanDone == 0)) {
            WiFi.scanNetworks(true, showHiddenNetworks); // async
            scanRunning = true;
        }
        if (scanRunning) {
            int n = WiFi.scanComplete();
            if (n >= 0) {
                aps.clear();
                for (int i = 0; i < n; i++) {
                    ApEntry ap;
                    memset(&ap, 0, sizeof(ap));
                    strncpy(ap.ssid, WiFi.SSID(i).c_str(), sizeof(ap.ssid) - 1);
                    ap.rssi = WiFi.RSSI(i);
                    ap.channel = (uint8_t)WiFi.channel(i);
                    ap.enc = (uint8_t)WiFi.encryptionType(i);
                    // stable colour from BSSID hash
                    const uint8_t *b = WiFi.BSSID(i);
                    uint32_t h = 0;
                    if (b)
                        for (int k = 0; k < 6; k++) h = h * 31 + b[k];
                    ap.color = PALETTE[h % PALETTE_SIZE];
                    aps.push_back(ap);
                }
                WiFi.scanDelete();
                scanRunning = false;
                lastScanDone = millis();
                if (highlight >= (int)aps.size()) highlight = (int)aps.size() - 1;
                logScan(aps);
                dirty = true;
            } else if (n == WIFI_SCAN_FAILED) {
                scanRunning = false;
                lastScanDone = millis();
            }
        }

        // ── Input ──
        if (check(SelPress)) {
            paused = !paused;
            Serial.printf("[WiFiAnalyzer] %s\n", paused ? "PAUSED" : "resumed");
            dirty = true;
        }
        if (!aps.empty() && check(NextPress)) {
            highlight = (highlight + 1) % (int)aps.size();
            dirty = true;
        }
        if (!aps.empty() && check(PrevPress)) {
            highlight = (highlight <= 0 ? (int)aps.size() : highlight) - 1;
            dirty = true;
        }

        if (dirty) {
            redraw();
            dirty = false;
        }
        yield();
    }

    if (haveSprite) spr.deleteSprite();
    WiFi.scanDelete();
    WiFi.mode(prevMode);
    Serial.println("[WiFiAnalyzer] closed");
}
