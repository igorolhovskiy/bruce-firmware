#include "wifi_analyzer.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <WiFi.h>
#include <globals.h>

// Phase 1 stub: prove the menu-registration path. Replaced with the graph in
// later phases.
void wifi_analyzer() {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(1);
    tft.drawCentreString("WiFi Analyzer", tftWidth / 2, tftHeight / 2 - 16, 1);
    tft.drawCentreString("scanning...", tftWidth / 2, tftHeight / 2, 1);
    tft.drawCentreString("[ESC] to exit", tftWidth / 2, tftHeight / 2 + 16, 1);

    Serial.println("[WiFiAnalyzer] opened (stub)");

    while (!check(EscPress)) { yield(); }

    Serial.println("[WiFiAnalyzer] closed");
}
