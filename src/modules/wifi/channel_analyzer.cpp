#if !defined(LITE_VERSION)
#include "channel_analyzer.h"

#include "esp_err.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/wifi/wifi_common.h"
#include <Arduino.h>
#include <globals.h>

// Ported from upstream Bruce (pr3y/Bruce #2578). AGPL, same project/license.

// 2.4GHz channels to sweep.
static const uint8_t CA_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
static const int CA_NCH = sizeof(CA_CHANNELS) / sizeof(CA_CHANNELS[0]);

// Load% at/above which a bar is drawn solid (busy) instead of dimmed.
static const uint8_t CA_BUSY_THRESHOLD = 50;

// Counters updated from the promiscuous RX callback for the *current* channel.
static volatile uint32_t ca_bytes = 0;
static volatile uint32_t ca_pkts = 0;
static volatile int8_t ca_rssi_peak = -128;

// Keep the callback minimal: just accumulate. Airtime is estimated in the loop.
static void IRAM_ATTR ca_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    if (!pkt) return;
    ca_pkts++;
    ca_bytes += pkt->rx_ctrl.sig_len;
    if (pkt->rx_ctrl.rssi > ca_rssi_peak) ca_rssi_peak = pkt->rx_ctrl.rssi;
}

// Tolerant WiFi bring-up. Unlike the sniffer (ESP_ERROR_CHECK), we never abort:
// if WiFi is already initialised/started we get ESP_ERR_WIFI_INIT_STATE (or
// similar) and just carry on — promiscuous mode works regardless.
static void ca_start_wifi() {
    ensureWifiPlatform();
    nvs_flash_init();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t e = esp_wifi_init(&cfg);
    if (e != ESP_OK && e != ESP_ERR_WIFI_INIT_STATE)
        Serial.printf("[ChAnalyzer] wifi_init: %s\n", esp_err_to_name(e));
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    e = esp_wifi_start();
    if (e != ESP_OK && e != ESP_ERR_WIFI_INIT_STATE)
        Serial.printf("[ChAnalyzer] wifi_start: %s\n", esp_err_to_name(e));
    esp_wifi_set_promiscuous(true);
    // Capture every frame type so the airtime estimate reflects real load.
    wifi_promiscuous_filter_t filt = {};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(ca_rx_cb);
}

static void ca_stop_wifi() {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_stop();
    wifiDisconnect();
    vTaskDelay(1 / portTICK_RATE_MS);
}

// Per-row draw caches so only changed rows/footer repaint (no periodic full
// redraw -> no flicker). Reset by ca_reset_cache() when the view (re)opens.
static uint8_t caLastLoad[12], caLastPeak[12];
static int8_t caLastRssi[12];
static int caLastCur = -1;
static String caLastFoot = "\x01";
static bool caCacheValid = false;

static void ca_reset_cache() {
    for (int i = 0; i < 12; i++) {
        caLastLoad[i] = 0xFF;
        caLastPeak[i] = 0xFF;
        caLastRssi[i] = 127;
    }
    caLastCur = -1;
    caLastFoot = "\x01";
    caCacheValid = false;
}

static void ca_draw(
    const uint8_t *load, const uint8_t *peak, const int8_t *rssi, uint8_t curCh, uint16_t dwell
) {
    const int x0 = 8;                  // left of bars
    const int top = 26;                // below title
    const int bottom = tftHeight - 16; // leave room for footer
    const int avail = bottom - top;
    const int rowH = avail / CA_NCH;
    const int labelW = 30;                  // "Ch11"
    const int valW = 30;                    // " 100%"
    const int barX = x0 + labelW;
    const int barW = tftWidth - barX - valW - 6;

    tft.setTextSize(FP);
    for (int i = 0; i < CA_NCH; i++) {
        uint8_t ch = CA_CHANNELS[i];
        bool isCur = (ch == curCh);
        bool wasCur = (caCacheValid && caLastCur == ch);
        bool dataChanged = !caCacheValid || load[ch] != caLastLoad[ch] ||
                           peak[ch] != caLastPeak[ch] || rssi[ch] != caLastRssi[ch];
        bool hiChanged = (isCur != wasCur);
        if (!dataChanged && !hiChanged) continue; // nothing to repaint on this row

        int y = top + i * rowH;
        int bh = rowH - 3;
        if (bh < 4) bh = 4;

        // Label: repaint only when the sweep highlight moves onto/off this row.
        // Done in place (opaque background) so there is no clear-to-bg flash.
        if (hiChanged || !caCacheValid) {
            tft.setTextColor(
                isCur ? bruceConfig.bgColor : bruceConfig.priColor,
                isCur ? bruceConfig.priColor : bruceConfig.bgColor
            );
            tft.fillRect(x0, y, labelW - 2, 9, isCur ? bruceConfig.priColor : bruceConfig.bgColor);
            tft.drawString("Ch" + String(ch), x0, y, 1);
        }

        // Bar: only when the measured load/peak changed (once per full sweep for a
        // given channel). Update the fill IN PLACE - colored portion then the empty
        // remainder - instead of clearing the whole bar first, so no flash.
        if (dataChanged) {
            if (!caCacheValid) tft.drawRect(barX, y, barW, bh, bruceConfig.priColor); // frame once
            int fillW = (barW - 2) * load[ch] / 100;
            uint16_t c = (load[ch] >= CA_BUSY_THRESHOLD) ? bruceConfig.priColor : TFT_DARKGREY;
            if (fillW > 0) tft.fillRect(barX + 1, y + 1, fillW, bh - 2, c);
            if (fillW < barW - 2) // paint the empty remainder (erases a shrunk bar)
                tft.fillRect(barX + 1 + fillW, y + 1, (barW - 2) - fillW, bh - 2, bruceConfig.bgColor);
            // peak-hold marker (drawn after the fill so it sits on top)
            int peakX = barX + 1 + (barW - 2) * peak[ch] / 100;
            if (peakX > barX + 1) tft.drawFastVLine(peakX, y + 1, bh - 2, TFT_RED);
            // value (opaque, padded so a shorter number erases the old one)
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            char v[6];
            snprintf(v, sizeof(v), "%3d%%", load[ch]);
            tft.drawString(v, barX + barW + 4, y, 1);
        }

        caLastLoad[ch] = load[ch];
        caLastPeak[ch] = peak[ch];
        caLastRssi[ch] = rssi[ch];
    }
    caLastCur = curCh;
    caCacheValid = true;

    // footer: current channel detail + signal meter + dwell (diffed)
    String foot = "Ch" + String(curCh) + " " + String(load[curCh]) + "% pk" + String(peak[curCh]) +
                  "% " + String(rssi[curCh]) + "dBm  dwell " + String(dwell) + "ms";
    if (foot != caLastFoot) {
        caLastFoot = foot;
        tft.fillRect(x0, tftHeight - 14, tftWidth - x0 - 6, 12, bruceConfig.bgColor);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawString(foot, x0, tftHeight - 13, 1);
    }
}

void channel_analyzer_setup() {
    returnToMenu = false;

    uint8_t load[12] = {0};
    uint8_t peak[12] = {0};
    int8_t rssi[12];
    for (int i = 0; i < 12; i++) rssi[i] = -128;

    uint16_t dwell = 350; // ms per channel, adjustable with Up/Down
    int idx = 0;

    ca_start_wifi();

    // Border + title drawn ONCE; the sweep loop only repaints changed rows/footer
    // (per-row diffing) so there is no periodic full redraw / flicker.
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("Channel Analyzer");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    padprintln("");
    padprintln(" sweeping 1-11 ...");
    ca_reset_cache(); // first ca_draw() repaints every row (clearing this message)
    delay(300);
    // Clear the content band once so the loading message can't peek between bars.
    tft.fillRect(6, 25, tftWidth - 12, tftHeight - 25 - 14, bruceConfig.bgColor);

    for (;;) {
        if (returnToMenu) break;
        if (check(EscPress)) {
            returnToMenu = true;
            break;
        }
        if (check(UpPress) && dwell < 1000) dwell += 100;   // longer dwell = more accurate
        if (check(DownPress) && dwell > 150) dwell -= 100;  // shorter dwell = faster sweep

        uint8_t ch = CA_CHANNELS[idx];
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

        // reset counters for this dwell window
        ca_bytes = 0;
        ca_pkts = 0;
        ca_rssi_peak = -128;

        uint32_t t0 = millis();
        while (millis() - t0 < dwell) {
            if (check(EscPress)) {
                returnToMenu = true;
                break;
            }
            vTaskDelay(20 / portTICK_PERIOD_MS);
        }
        if (returnToMenu) break;

        // Estimate airtime utilisation: bytes at a conservative ~6Mbps baseline
        // plus per-frame preamble/IFS overhead. Clamp to 0-100%.
        uint32_t airtime_us = (ca_bytes * 8UL) / 6UL + ca_pkts * 60UL;
        uint32_t dwell_us = (uint32_t)dwell * 1000UL;
        uint32_t l = dwell_us ? (airtime_us * 100UL / dwell_us) : 0;
        if (l > 100) l = 100;

        load[ch] = (uint8_t)l;
        if (load[ch] > peak[ch]) peak[ch] = load[ch];
        rssi[ch] = (ca_rssi_peak == -128) ? 0 : ca_rssi_peak;

        ca_draw(load, peak, rssi, ch, dwell);

        idx = (idx + 1) % CA_NCH;
    }

    ca_stop_wifi();
}

#endif
