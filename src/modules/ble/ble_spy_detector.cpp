#include "ble_spy_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

// Phase 0 placeholder - spy-gadget classification lands in Phase 4 (extends the
// relocated tracker detector's signature table).
void ble_spy_detector() {
    Serial.println("[BleSpy] stub - BLE spy-tag detector (Phase 4, not yet implemented)");
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString("BLE Spy Tags", tftWidth / 2, 20, 1);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Coming soon (Phase 4):", 8, 60);
    tft.drawString("hidden BLE cams / bugs / gadgets.", 8, 76);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString("Receive-only. Press ESC to exit.", 8, tftHeight - 20);
    while (!check(EscPress)) delay(30);
}
