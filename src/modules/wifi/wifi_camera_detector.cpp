#include "wifi_camera_detector.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

// Phase 0 placeholder - the real passive capture core lands in Phase 1.
void wifi_camera_detector() {
    Serial.println("[CamDetect] stub - passive WiFi camera detector (Phase 1, not yet implemented)");
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString("WiFi Camera", tftWidth / 2, 20, 1);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Coming soon (Phase 1):", 8, 60);
    tft.drawString("passive OUI/SSID camera scan.", 8, 76);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString("Receive-only. Press ESC to exit.", 8, tftHeight - 20);
    while (!check(EscPress)) delay(30);
}
