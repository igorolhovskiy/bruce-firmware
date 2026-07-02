#if !defined(LITE_VERSION)
#include "LoRaRecon.h"
#include "core/display.h"
#include <Arduino.h>
#include <globals.h>

// Phase 2: menu-registration checkpoint only. The radio is not touched yet —
// that lands in Phase 3 (promiscuous RX bring-up).
void loraRecon() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
    tft.drawCentreString("LoRa Recon", tftWidth / 2, 10, 1);

    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawCentreString("LoRa Recon - starting...", tftWidth / 2, tftHeight / 2, 1);
    tft.drawCentreString("(passive, receive-only)", tftWidth / 2, tftHeight / 2 + 12, 1);

    Serial.println("[LoRaRecon] LoRa Recon - starting... (passive, receive-only)");

    while (true) {
        if (check(EscPress)) break;
        delay(20);
    }

    Serial.println("[LoRaRecon] exiting");
}
#endif
