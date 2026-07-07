#include "CounterSurveilMenu.h"

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_spy_detector.h"
#include "modules/ble/tracker_detector.h"
#include "modules/wifi/drone_remoteid.h"
#include "modules/wifi/follower_scan.h"
#include "modules/wifi/rogue_ap.h"
#include "modules/wifi/wifi_camera_detector.h"
#include <globals.h>

void CounterSurveilMenu::optionsMenu() {
    options.clear();

    // Relocated from the BLE menu - the app's first known-good entry (Phase 0).
    options.push_back({"Tracker Detector", tracker_detector});
    options.push_back({"WiFi Camera", wifi_camera_detector});
    options.push_back({"Drone Remote ID", drone_remoteid});
    options.push_back({"Rogue AP / Karma", rogue_ap});
    options.push_back({"BLE Spy Tags", ble_spy_detector});
    options.push_back({"Follower Scan", follower_scan});

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
