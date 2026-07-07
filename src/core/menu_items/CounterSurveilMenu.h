#ifndef __COUNTER_SURVEIL_MENU_H__
#define __COUNTER_SURVEIL_MENU_H__

#include <MenuItemInterface.h>

// Top-level "Detector" app: a suite of passive (receive-only) counter-surveillance
// detectors that span WiFi + BLE (hidden cameras, drone Remote ID, rogue APs, BLE
// spy tags, followers, and the relocated tracker detector). Its optionsMenu() opens
// the "Counter-Surveil" submenu. Generic placeholder icon for now (an eye).
class CounterSurveilMenu : public MenuItemInterface {
public:
    CounterSurveilMenu() : MenuItemInterface("Detector") {}

    void optionsMenu(void);
    void drawIcon(float scale);
    bool hasTheme() { return false; }
    String themePath() { return ""; }
};

#endif
