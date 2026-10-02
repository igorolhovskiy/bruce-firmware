#include "tool_help.h"
#if !defined(LITE_VERSION)

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/scrollableTextArea.h"
#include <globals.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Tool Help: a submenu of a section's tools, each opening a scrollable manual.
// Up/Down scroll, ESC/SEL back. Content is plain text (ScrollableTextArea wraps).
// ─────────────────────────────────────────────────────────────────────────────

namespace {

struct ToolHelp {
    const char *name;
    const char *body;
};

void showToolHelp(const char *title, const char *body) {
    ScrollableTextArea area{String(title)};
    area.fromString(String(body));
    area.draw(true);
    while (check(SelPress)) yield(); // drain the SEL that opened this page
    delay(150);
    while (true) {
        if (check(EscPress) || check(SelPress)) break;
        if (check(PrevPress)) {
            area.scrollUp();
            area.draw();
        }
        if (check(NextPress)) {
            area.scrollDown();
            area.draw();
        }
        delay(30);
    }
}

void toolHelpMenu(const char *title, const ToolHelp *tools, size_t n) {
    std::vector<Option> options;
    for (size_t i = 0; i < n; i++) {
        const ToolHelp *t = &tools[i];
        options.push_back({String(t->name), [t]() { showToolHelp(t->name, t->body); }});
    }
    options.push_back({"Back", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, title);
}

// ── WiFi section ──────────────────────────────────────────────────────────────
const ToolHelp WIFI_TOOLS[] = {
    {"WiFi Analyzer",
     "Passive. Visualises nearby 2.4GHz APs as signal-strength bars per channel "
     "(dBm vs ch 1-14).\n\nUse: see which APs/channels are busiest and strongest. "
     "RX-only, never transmits."},
    {"Channel Analyzer",
     "Passive. Sweeps ch 1-11 and estimates per-channel airtime LOAD% with peak-"
     "hold and a signal meter.\n\nUp/Down: change dwell (longer=more accurate). "
     "Use: pick a clear channel / spot congestion or jamming-level traffic."},
    {"Passive Recon",
     "RX-only promiscuous capture. SEL cycles 3 views:\n- Client probe requests + "
     "the SSIDs they look for\n- Deauth/disassoc FLOOD detector (rate, top sources)\n"
     "- AP list with encryption + 802.11w/PMF (deauth-immune APs highlighted).\n"
     "Logs to SD. Never transmits."},
    {"Sniffer",
     "Captures raw 802.11 frames to a PCAP file on the SD card for later analysis "
     "in Wireshark. Passive."},
    {"Wifi Atks",
     "ACTIVE / TRANSMITS. Offensive tests: deauth, beacon spam, etc.\n\nWARNING: "
     "only use on networks you own or are authorised to test. Disrupts service and "
     "may be illegal otherwise."},
    {"Evil Portal",
     "ACTIVE / TRANSMITS. Starts a fake AP + captive portal to capture entered "
     "credentials.\n\nWARNING: authorised testing only. Do not deploy against "
     "people without consent."},
};

// ── BLE section ───────────────────────────────────────────────────────────────
const ToolHelp BLE_TOOLS[] = {
    {"BLE Scan", "Passive. Lists nearby BLE devices (address, name, RSSI). Good for "
                 "seeing what is advertising around you."},
    {"BLE Spam",
     "ACTIVE / TRANSMITS. Floods BLE advertisements (Apple/Android/etc. pair popups).\n\n"
     "WARNING: disruptive and region-restricted; authorised testing / demos only."},
    {"BLE Suite", "Scanning plus connect/enumerate/interaction tools for BLE devices. "
                  "Some actions transmit - use responsibly."},
    {"Bad BLE", "ACTIVE / TRANSMITS. BLE HID (DuckyScript) injection - acts as a "
                "keyboard to a paired host. Authorised testing only."},
    {"BLE Keyboard", "Turns the device into a Bluetooth keyboard for a host you control."},
    {"iBeacon", "ACTIVE / TRANSMITS. Broadcasts an Apple iBeacon advertisement."},
    {"LED Badge", "Pushes text/animations to BLE LED name badges over the air."},
};

// ── Detector (Counter-Surveil) section — all PASSIVE / RX-only ─────────────────
const ToolHelp DET_TOOLS[] = {
    {"Ambient Watch",
     "The all-in-one watch. Time-slices WiFi + BLE and collects every threat below "
     "into ONE list, sorted by confidence.\n\nf: confidence filter (All/Med+/High). "
     "SEL: details. A High hit raises an alert banner. Logs to /BruceDetector/"
     "watch.csv. Passive.\n\ng: grey-after (1m/2m/5m/10m/off, default 2m). A device "
     "not heard for that long is greyed and sinks - it passed by. It re-lights if "
     "heard again. Shared with the other Detector lists.\n\nP / magenta = PERSISTENT: heard "
     "over 10+ min in 6+ distinct minutes. Moving? It is following you. Staying put? "
     "Probably fixed nearby."},
    {"Tracker Detector",
     "Finds BLE item trackers that may be following you: Apple Find My/AirTag, "
     "Samsung SmartTag, Tile.\n\nHint: AirTags rotate their address, so a moving "
     "tracker is the real signal."},
    {"WiFi Camera",
     "Flags WiFi devices whose MAC vendor (OUI) or SSID matches a camera / ALPR / "
     "Flock / Ring vendor. H/M/L confidence.\n\nTune the SSID include/exclude lists "
     "in bruce.conf (camSsidPatterns / camSsidExclude)."},
    {"Stream Cam",
     "Catches UNKNOWN-vendor cameras by TRAFFIC SHAPE: sustained, mostly-large, "
     "upstream data frames = video-like.\n\nSEL a candidate -> motion test: hold "
     "still for the baseline, then wave at the suspected camera; a correlated "
     "packet-rate SPIKE confirms it (HIGH). Heuristic - not proof."},
    {"Drone Remote ID",
     "Decodes Open Drone ID / ASTM F3411 broadcasts (WiFi + BLE): lists nearby "
     "drones with position AND the operator's location."},
    {"Rogue AP / Karma",
     "Flags evil-twin / Karma APs (one BSSID answering many SSIDs), and deauth-"
     "flood sources (jammer / MITM kick)."},
    {"BLE Spy Tags",
     "Flags BLE hidden cameras / recorders / doorbells via vendor OUI, device-name "
     "patterns, and company IDs - plus Meta/Ray-Ban/Snap camera glasses."},
    {"Pentest Gear",
     "Detects nearby hacking hardware over BLE: Flipper Zero (exact service-UUID / "
     "company-ID / OUI). See WiFi Pentest for the WiFi side."},
    {"WiFi Pentest",
     "Detects pentest gear on WiFi: Hak5 Pineapple (setup SSID + Hak5 MACs), ESP "
     "deauther (pwned SSID), and Pwnagotchi (pwnd_tot beacon field, shows its name)."},
    {"Follower Scan",
     "Dwell-time model over WiFi-probe + BLE addresses. Mark 'I moved' to surface "
     "an address that keeps appearing wherever you go (a possible tail)."},
    {"Block-Ack DoS",
     "Passive counterpart to the BAR DoS attack: watches 802.11 Block-Ack-Request "
     "rate per transmitter and flags a flood (>=12 BAR/s)."},
};

} // namespace

void wifiToolHelp() { toolHelpMenu("WiFi Tool Help", WIFI_TOOLS, sizeof(WIFI_TOOLS) / sizeof(WIFI_TOOLS[0])); }
void bleToolHelp() { toolHelpMenu("BLE Tool Help", BLE_TOOLS, sizeof(BLE_TOOLS) / sizeof(BLE_TOOLS[0])); }
void detectorToolHelp() {
    toolHelpMenu("Detector Tool Help", DET_TOOLS, sizeof(DET_TOOLS) / sizeof(DET_TOOLS[0]));
}

#endif
