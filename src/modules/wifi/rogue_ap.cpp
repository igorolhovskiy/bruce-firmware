#include "rogue_ap.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

// Phase 0 placeholder - Karma / evil-twin / deauth heuristics land in Phase 3.
void rogue_ap() {
    Serial.println("[RogueAP] stub - rogue AP / Karma detector (Phase 3, not yet implemented)");
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString("Rogue AP / Karma", tftWidth / 2, 20, 1);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Coming soon (Phase 3):", 8, 60);
    tft.drawString("Karma, evil-twin, deauth flood.", 8, 76);
    tft.setTextColor(TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString("Receive-only. Press ESC to exit.", 8, tftHeight - 20);
    while (!check(EscPress)) delay(30);
}
