#include "follower_scan.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

// Phase 0 placeholder - the dwell-time follower model lands in Phase 5.
void follower_scan() {
    Serial.println("[Follower] stub - follower / dwell-time scan (Phase 5, not yet implemented)");
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString("Follower Scan", tftWidth / 2, 20, 1);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Coming soon (Phase 5):", 8, 60);
    tft.drawString("dwell-time tail detection.", 8, 76);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString("Receive-only. Press ESC to exit.", 8, tftHeight - 20);
    while (!check(EscPress)) delay(30);
}
