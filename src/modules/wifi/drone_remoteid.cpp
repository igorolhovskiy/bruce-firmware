#include "drone_remoteid.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

// Phase 0 placeholder - Open Drone ID WiFi + BLE decode lands in Phase 2.
void drone_remoteid() {
    Serial.println("[DroneRID] stub - Open Drone ID detector (Phase 2, not yet implemented)");
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString("Drone Remote ID", tftWidth / 2, 20, 1);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Coming soon (Phase 2):", 8, 60);
    tft.drawString("Open Drone ID WiFi + BLE decode.", 8, 76);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString("Receive-only. Press ESC to exit.", 8, tftHeight - 20);
    while (!check(EscPress)) delay(30);
}
