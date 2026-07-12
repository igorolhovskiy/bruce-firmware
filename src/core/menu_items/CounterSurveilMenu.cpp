#include "CounterSurveilMenu.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "modules/ble/ble_spy_detector.h"
#include "modules/ble/tracker_detector.h"
#include "modules/wifi/blockack_detector.h"
#include "modules/wifi/drone_remoteid.h"
#include "modules/wifi/follower_scan.h"
#include "modules/wifi/rogue_ap.h"
#include "modules/wifi/wifi_camera_detector.h"
#include <globals.h>

// About / Limits screen: states the passive nature and the hardware non-goals
// on-device so the suite doesn't over-promise. Loops until ESC.
static void counterSurveilAbout() {
    const char *lines[] = {
        "Counter-Surveil (Detector)",
        "",
        "All detectors are PASSIVE /",
        "receive-only: never transmit,",
        "beacon, deauth or associate.",
        "",
        "Cannot detect (hardware limits):",
        "- cellular trackers / IMSI (no",
        "  cellular modem)",
        "- analog RF bugs / wireless mics",
        "  (no broadband SDR)",
        "- optical / lens-glint cameras",
        "  (no optical sensor)",
        "- Zigbee/Thread 802.15.4",
        "",
        "Hits are heuristic - see confidence.",
        "Press ESC to go back.",
    };
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FP);
    int n = sizeof(lines) / sizeof(lines[0]);
    for (int i = 0; i < n; i++) {
        uint16_t fg = i == 0 ? bruceConfig.priColor
                      : (lines[i][0] == '-' || lines[i][0] == ' ') ? TFT_WHITE
                                                                   : TFT_YELLOW;
        tft.setTextColor(fg, bruceConfig.bgColor);
        tft.drawString(lines[i], 6, 4 + i * 12);
    }
    while (!check(EscPress)) delay(30);
}

void CounterSurveilMenu::optionsMenu() {
    options.clear();

    // Relocated from the BLE menu - the app's first known-good entry (Phase 0).
    options.push_back({"Tracker Detector", tracker_detector});
    options.push_back({"WiFi Camera", wifi_camera_detector});
    options.push_back({"Drone Remote ID", drone_remoteid});
    options.push_back({"Rogue AP / Karma", rogue_ap});
    options.push_back({"BLE Spy Tags", ble_spy_detector});
    options.push_back({"Follower Scan", follower_scan});
    options.push_back({"Block-Ack DoS", blockack_detector});
    options.push_back({"About / Limits", counterSurveilAbout});

    addOptionToMainMenu();

    loopOptions(options, MENU_TYPE_SUBMENU, "Counter-Surveil");

    options.clear();
}

// Generic placeholder icon: an eye (an outlined ellipse with a filled pupil). A
// themed PNG can replace this later via the theme hooks. A few primitive calls,
// sized by `scale`, in the theme's primary colour.
void CounterSurveilMenu::drawIcon(float scale) {
    clearIconArea();

    int rx = scale * 26;      // eye half-width
    int ry = scale * 15;      // eye half-height
    int pupil = scale * 7;    // pupil radius

    // Eye outline (two concentric ellipses read as a lid), then the pupil.
    tft.drawEllipse(iconCenterX, iconCenterY, rx, ry, bruceConfig.priColor);
    tft.drawEllipse(iconCenterX, iconCenterY, rx - 1, ry - 1, bruceConfig.priColor);
    tft.fillCircle(iconCenterX, iconCenterY, pupil, bruceConfig.priColor);
    // Highlight dot to sell the "eye" read (background colour bite out of the pupil).
    tft.fillCircle(iconCenterX + pupil / 3, iconCenterY - pupil / 3, pupil / 3, bruceConfig.bgColor);
}
