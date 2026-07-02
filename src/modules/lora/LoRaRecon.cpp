#if !defined(LITE_VERSION)
#include "LoRaRecon.h"
#include "core/configPins.h"
#include "core/display.h"
#include "modules/lora/LoRaRF.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <globals.h>

extern BruceConfigPins bruceConfigPins;

namespace {

// Phase 3: single fixed channel/SF, promiscuous raw capture - no decoding
// yet (Phase 4) and no sweep yet (Phase 5). RECEIVE-ONLY: this file never
// calls a transmit API on the radio.
constexpr float RECON_FREQ_MHZ = 868.1f; // EU868 uplink channel (§8 channel plan)
constexpr float RECON_BW_KHZ = 125.0f;
constexpr uint8_t RECON_SF = 7;
constexpr uint8_t RECON_CR = 5; // coding rate 4/5
constexpr uint8_t RECON_SYNC_WORD = 0x34; // LoRaWAN public sync word
constexpr size_t RECON_PREAMBLE = 8;
constexpr uint32_t HEARTBEAT_MS = 3000;
constexpr uint32_t REDRAW_MS = 250;

SPIClass *reconSpi = nullptr;
Module *reconModule = nullptr;
SX1262 *reconRadio = nullptr;
volatile bool reconIrqEnabled = true;
volatile bool reconPacketReceived = false;
uint32_t reconPacketCount = 0;
String lastFrameSummary = "no frames yet";

void IRAM_ATTR onReconPacket() {
    if (!reconIrqEnabled) return;
    reconPacketReceived = true;
}

void clearReconRadio() {
    if (reconRadio) {
        delete reconRadio;
        reconRadio = nullptr;
    }
    if (reconModule) {
        delete reconModule;
        reconModule = nullptr;
    }
}

String toHex(const uint8_t *data, size_t len) {
    String hex;
    hex.reserve(len * 2);
    char byteStr[3];
    for (size_t i = 0; i < len; i++) {
        snprintf(byteStr, sizeof(byteStr), "%02X", data[i]);
        hex += byteStr;
    }
    return hex;
}

bool startReconRadio() {
    reconPacketReceived = false;
    reconIrqEnabled = true;

    if (getLoraCsPin() == GPIO_NUM_NC || bruceConfigPins.LoRa_bus.mosi == GPIO_NUM_NC ||
        bruceConfigPins.LoRa_bus.miso == GPIO_NUM_NC || bruceConfigPins.LoRa_bus.sck == GPIO_NUM_NC) {
        Serial.println("[LoRaRecon] LoRa pins not configured!");
        displayError("LoRa pins not configured!", true);
        return false;
    }
    const int irqPin = getLoraIrqPin();
    if (irqPin == GPIO_NUM_NC) {
        Serial.println("[LoRaRecon] LoRa IRQ pin not configured!");
        displayError("LoRa IRQ pin not configured!", true);
        return false;
    }
    const int busyPin = getLoraBusyPin();
    if (busyPin == GPIO_NUM_NC) { Serial.println("[LoRaRecon] Warning: SX1262 BUSY pin not configured"); }

    reconSpi = selectLoraSPIBus();
    clearReconRadio();
    reconModule = new Module(getLoraCsPin(), irqPin, getLoraResetPin(), busyPin, *reconSpi);
    reconRadio = new SX1262(reconModule);

    int state = reconRadio->begin(RECON_FREQ_MHZ);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setBandwidth(RECON_BW_KHZ);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setSpreadingFactor(RECON_SF);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setCodingRate(RECON_CR);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setPreambleLength(RECON_PREAMBLE);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setSyncWord(RECON_SYNC_WORD);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->invertIQ(false); // uplink: standard IQ
    if (state == RADIOLIB_ERR_NONE) { reconRadio->setDio1Action(onReconPacket); }
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->startReceive();

    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[LoRaRecon] Radio init failed! Err %d\n", state);
        displayError("LoRa Recon init failed", true);
        clearReconRadio();
        return false;
    }

    Serial.printf(
        "[LoRaRecon] Listening: freq=%.3fMHz sf=%u bw=%.1fkHz cr=4/%u sync=0x%02X preamble=%u "
        "(receive-only, radio will never transmit)\n",
        RECON_FREQ_MHZ, RECON_SF, RECON_BW_KHZ, RECON_CR, RECON_SYNC_WORD, (unsigned)RECON_PREAMBLE
    );
    return true;
}

void stopReconRadio() {
    if (reconRadio) reconRadio->standby();
    clearReconRadio();
}

void processReconPacket() {
    if (!reconPacketReceived || !reconRadio) return;
    reconIrqEnabled = false;
    reconPacketReceived = false;

    size_t len = reconRadio->getPacketLength();
    if (len == 0 || len > 255) {
        reconRadio->startReceive();
        reconIrqEnabled = true;
        return;
    }

    uint8_t buf[255];
    int state = reconRadio->readData(buf, len);
    bool crcOk = (state == RADIOLIB_ERR_NONE);
    bool crcMismatch = (state == RADIOLIB_ERR_CRC_MISMATCH);

    if (crcOk || crcMismatch) {
        float rssi = reconRadio->getRSSI();
        float snr = reconRadio->getSNR();
        float airtimeMs = reconRadio->getTimeOnAir(len) / 1000.0f;
        String hex = toHex(buf, len);
        reconPacketCount++;

        Serial.printf(
            "[LoRaRecon] RX #%lu len=%u rssi=%.1fdBm snr=%.1fdB airtime=%.2fms crc=%s hex=%s\n",
            (unsigned long)reconPacketCount, (unsigned)len, rssi, snr, airtimeMs,
            crcOk ? "OK" : "MISMATCH", hex.c_str()
        );

        lastFrameSummary = "#" + String(reconPacketCount) + " len=" + String((unsigned)len) +
                            " rssi=" + String(rssi, 1) + "dBm" + (crcOk ? "" : " CRC!");
    } else {
        Serial.printf("[LoRaRecon] RX read failed: %d\n", state);
    }

    reconRadio->startReceive();
    reconIrqEnabled = true;
}

} // namespace

void loraRecon() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
    tft.drawCentreString("LoRa Recon", tftWidth / 2, 10, 1);

    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    char cfgLine[48];
    snprintf(cfgLine, sizeof(cfgLine), "%.3f MHz  SF%u  BW%.0f", RECON_FREQ_MHZ, RECON_SF, RECON_BW_KHZ);
    tft.drawCentreString(cfgLine, tftWidth / 2, tftHeight / 2 - 20, 1);
    tft.drawCentreString("passive, receive-only", tftWidth / 2, tftHeight / 2 - 8, 1);

    reconPacketCount = 0;
    lastFrameSummary = "no frames yet";

    if (!startReconRadio()) {
        while (true) {
            if (check(EscPress)) return;
            delay(20);
        }
    }

    uint32_t lastHeartbeat = millis();
    uint32_t lastRedraw = 0;
    while (true) {
        processReconPacket();

        if (millis() - lastHeartbeat > HEARTBEAT_MS) {
            lastHeartbeat = millis();
            Serial.printf(
                "[LoRaRecon] listening... packets=%lu uptime=%lus\n", (unsigned long)reconPacketCount,
                (unsigned long)(millis() / 1000)
            );
        }

        if (millis() - lastRedraw > REDRAW_MS) {
            lastRedraw = millis();
            tft.fillRect(0, tftHeight / 2 + 4, tftWidth, 40, TFT_BLACK);
            tft.setTextColor(TFT_WHITE, TFT_BLACK);
            char countLine[24];
            snprintf(countLine, sizeof(countLine), "Packets: %lu", (unsigned long)reconPacketCount);
            tft.drawCentreString(countLine, tftWidth / 2, tftHeight / 2 + 6, 1);
            tft.drawCentreString(lastFrameSummary, tftWidth / 2, tftHeight / 2 + 18, 1);
        }

        if (check(EscPress)) break;
        delay(5);
    }

    stopReconRadio();
    Serial.println("[LoRaRecon] stopped, exiting");
}
#endif
