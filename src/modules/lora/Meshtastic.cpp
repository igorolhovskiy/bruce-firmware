#if !defined(LITE_VERSION)
#include "Meshtastic.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <Arduino.h>
#include <globals.h>

// ---------------------------------------------------------------------------
// Phase 2: menu-path validation stub only. Radio bring-up, crypto, protobuf,
// UI, and TX are added in later phases. This just proves the "Meshtastic" LoRa
// submenu entry opens a screen and exits cleanly on Backspace.
// ---------------------------------------------------------------------------

void meshtasticChannel() {
    Serial.println("[Meshtastic] opening (LongFast / EU868, placeholder)");

    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
    tft.drawCentreString("Meshtastic LF", tftWidth / 2, 10, 1);

    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawCentreString("LongFast - EU868 - 869.525 MHz", tftWidth / 2, tftHeight / 2 - 20, 1);
    tft.drawCentreString("SF11 / BW250 / CR4:5", tftWidth / 2, tftHeight / 2 - 8, 1);
    tft.drawCentreString("starting...", tftWidth / 2, tftHeight / 2 + 8, 1);

    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawCentreString("Backspace to exit", tftWidth / 2, tftHeight - 20, 1);

    while (true) {
        if (check(EscPress)) break;
        delay(20);
    }
    Serial.println("[Meshtastic] exit");
}
#endif
