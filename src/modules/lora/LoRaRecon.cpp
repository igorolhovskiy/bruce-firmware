#if !defined(LITE_VERSION)
#include "LoRaRecon.h"
#include "LoRaWANParser.h"
#include "core/configPins.h"
#include "core/display.h"
#include "modules/lora/LoRaRF.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <globals.h>

extern BruceConfigPins bruceConfigPins;

namespace {

// RECEIVE-ONLY: this file never calls a transmit API on the radio.
constexpr float RECON_BW_KHZ = 125.0f;
constexpr uint8_t RECON_CR = 5; // coding rate 4/5
constexpr uint8_t RECON_SYNC_WORD = 0x34; // LoRaWAN public sync word
constexpr size_t RECON_PREAMBLE = 8;
constexpr uint32_t HEARTBEAT_MS = 3000;
constexpr uint32_t REDRAW_MS = 250;

// §8 EU868 channel plan: 8 uplink channels, one RX2 downlink channel.
constexpr float EU868_CHANNELS_MHZ[8] = {867.1f, 867.3f, 867.5f, 867.7f, 867.9f, 868.1f, 868.3f, 868.5f};
constexpr size_t EU868_CHANNEL_COUNT = 8;
constexpr float RX2_FREQ_MHZ = 869.525f;
constexpr uint8_t RX2_SF = 12;

// Per-SF dwell table (§8): one full 8-channel x 6-SF sweep = sum(dwell)*8 = 50s*8 = 400s.
struct SfDwell {
    uint8_t sf;
    uint32_t dwellMs;
};
constexpr SfDwell SF_DWELL_TABLE[] = {
    {7, 2000}, {8, 3000}, {9, 5000}, {10, 8000}, {11, 12000}, {12, 20000}
};
constexpr size_t SF_DWELL_COUNT = sizeof(SF_DWELL_TABLE) / sizeof(SF_DWELL_TABLE[0]);
constexpr uint32_t RX2_DWELL_MS = 20000; // reuse the SF12 dwell for the periodic RX2 park

struct ComboStats {
    uint32_t packetCount = 0;
    float lastRssi = 0;
    uint32_t lastDevAddr = 0;
    bool hasLastDevAddr = false;
};

SPIClass *reconSpi = nullptr;
Module *reconModule = nullptr;
SX1262 *reconRadio = nullptr;
volatile bool reconIrqEnabled = true;
volatile bool reconPacketReceived = false;
uint32_t reconPacketCount = 0;
String lastFrameSummary = "no frames yet";

enum class SweepStage { Channel, Rx2 };
SweepStage sweepStage = SweepStage::Channel;
size_t sweepChannelIdx = 0;
size_t sweepSfIdx = 0;
uint32_t stageStartMs = 0;
bool lockEnabled = false;
size_t lockedSfIdx = 0; // meaningful only while lockEnabled
ComboStats comboStats[EU868_CHANNEL_COUNT][SF_DWELL_COUNT];
uint32_t rx2PacketCount = 0;

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

// Reconfigures the already-initialized radio for a new frequency/SF/IQ and
// resumes continuous RX. Only ever calls standby()/setters/startReceive() -
// never a transmit API.
bool retuneRadio(float freqMHz, uint8_t sf, bool invertIq) {
    if (!reconRadio) return false;
    reconIrqEnabled = false;

    int state = reconRadio->standby();
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setFrequency(freqMHz);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setSpreadingFactor(sf);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->invertIQ(invertIq);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->startReceive();

    reconIrqEnabled = true;
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[LoRaRecon] retune failed freq=%.3fMHz sf=%u err=%d\n", freqMHz, sf, state);
        return false;
    }
    return true;
}

void enterChannel(size_t chIdx, size_t sfIdx) {
    sweepStage = SweepStage::Channel;
    sweepChannelIdx = chIdx;
    sweepSfIdx = sfIdx;
    stageStartMs = millis();
    retuneRadio(EU868_CHANNELS_MHZ[chIdx], SF_DWELL_TABLE[sfIdx].sf, false); // uplink: standard IQ
    Serial.printf(
        "[LoRaRecon] sweep -> channel %u/%u %.3fMHz SF%u%s\n", (unsigned)(chIdx + 1),
        (unsigned)EU868_CHANNEL_COUNT, EU868_CHANNELS_MHZ[chIdx], SF_DWELL_TABLE[sfIdx].sf,
        lockEnabled ? " [LOCKED]" : ""
    );
}

void enterRx2() {
    sweepStage = SweepStage::Rx2;
    stageStartMs = millis();
    retuneRadio(RX2_FREQ_MHZ, RX2_SF, true); // RX2 downlink: inverted IQ
    Serial.printf("[LoRaRecon] sweep -> RX2 %.3fMHz SF%u (inverted IQ)\n", RX2_FREQ_MHZ, RX2_SF);
}

uint32_t currentDwellMs() {
    if (sweepStage == SweepStage::Rx2) return RX2_DWELL_MS;
    return SF_DWELL_TABLE[lockEnabled ? lockedSfIdx : sweepSfIdx].dwellMs;
}

void advanceSweep() {
    if (sweepStage == SweepStage::Rx2) {
        enterChannel(0, lockEnabled ? lockedSfIdx : 0);
        return;
    }
    if (lockEnabled) {
        // Recommended lock mode: fix SF, keep hopping channels.
        size_t nextCh = sweepChannelIdx + 1;
        if (nextCh >= EU868_CHANNEL_COUNT) {
            enterRx2();
        } else {
            enterChannel(nextCh, lockedSfIdx);
        }
        return;
    }
    size_t nextSf = sweepSfIdx + 1;
    if (nextSf < SF_DWELL_COUNT) {
        enterChannel(sweepChannelIdx, nextSf);
        return;
    }
    size_t nextCh = sweepChannelIdx + 1;
    if (nextCh >= EU868_CHANNEL_COUNT) {
        enterRx2();
    } else {
        enterChannel(nextCh, 0);
    }
}

void updateSweep() {
    if (millis() - stageStartMs >= currentDwellMs()) advanceSweep();
}

void toggleLock() {
    lockEnabled = !lockEnabled;
    if (lockEnabled) {
        lockedSfIdx = (sweepStage == SweepStage::Channel) ? sweepSfIdx : 0;
        Serial.printf(
            "[LoRaRecon] LOCK enabled: SF%u fixed, hopping channels only\n", SF_DWELL_TABLE[lockedSfIdx].sf
        );
    } else {
        Serial.println("[LoRaRecon] LOCK disabled: resuming full channel x SF sweep");
    }
}

void resetStats() {
    for (size_t c = 0; c < EU868_CHANNEL_COUNT; c++) {
        for (size_t s = 0; s < SF_DWELL_COUNT; s++) comboStats[c][s] = ComboStats();
    }
    rx2PacketCount = 0;
    reconPacketCount = 0;
    lastFrameSummary = "no frames yet";
    Serial.println("[LoRaRecon] stats reset");
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

    int state = reconRadio->begin(EU868_CHANNELS_MHZ[0]);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setBandwidth(RECON_BW_KHZ);
    if (state == RADIOLIB_ERR_NONE) state = reconRadio->setSpreadingFactor(SF_DWELL_TABLE[0].sf);
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
        "[LoRaRecon] Radio up: bw=%.1fkHz cr=4/%u sync=0x%02X preamble=%u (receive-only, "
        "radio will never transmit). Starting sweep.\n",
        RECON_BW_KHZ, RECON_CR, RECON_SYNC_WORD, (unsigned)RECON_PREAMBLE
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
            "[LoRaRecon] RX #%lu %s len=%u rssi=%.1fdBm snr=%.1fdB airtime=%.2fms crc=%s hex=%s\n",
            (unsigned long)reconPacketCount,
            sweepStage == SweepStage::Rx2 ? "RX2" : (String("ch") + String((unsigned)(sweepChannelIdx + 1))).c_str(),
            (unsigned)len, rssi, snr, airtimeMs, crcOk ? "OK" : "MISMATCH", hex.c_str()
        );

        LoRaWANFrame decoded = parseLoRaWANFrame(buf, len);
        Serial.printf("[LoRaRecon] decoded: %s\n", decoded.mtypeName.c_str());
        for (const String &line : describeLoRaWANFrame(decoded)) {
            Serial.print("  - ");
            Serial.println(line);
        }

        if (sweepStage == SweepStage::Channel) {
            ComboStats &cs = comboStats[sweepChannelIdx][lockEnabled ? lockedSfIdx : sweepSfIdx];
            cs.packetCount++;
            cs.lastRssi = rssi;
            if (decoded.isDataFrame) {
                cs.lastDevAddr = decoded.devAddr;
                cs.hasLastDevAddr = true;
            }
        } else {
            rx2PacketCount++;
        }

        lastFrameSummary = "#" + String(reconPacketCount) + " " + decoded.mtypeName + " rssi=" +
                            String(rssi, 1) + "dBm" + (crcOk ? "" : " CRC!");
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
    tft.drawCentreString("EU868: 8ch x SF7-12, RX2 parked periodically", tftWidth / 2, tftHeight / 2 - 30, 1);
    tft.drawCentreString("passive, receive-only", tftWidth / 2, tftHeight / 2 - 18, 1);

    // Deterministic parser check (synthetic vectors, no radio traffic needed)
    // runs every time this screen opens, so a regression is always visible.
    bool selfTestOk = runLoRaWANParserSelfTest();
    tft.setTextColor(selfTestOk ? TFT_GREEN : TFT_RED, TFT_BLACK);
    tft.drawCentreString(
        selfTestOk ? "parser self-test: OK" : "parser self-test: FAILED", tftWidth / 2, tftHeight / 2 - 6, 1
    );
    tft.setTextColor(TFT_WHITE, TFT_BLACK);

    resetStats();
    lockEnabled = false;

    if (!startReconRadio()) {
        while (true) {
            if (check(EscPress)) return;
            delay(20);
        }
    }
    enterChannel(0, 0);

    uint32_t lastHeartbeat = millis();
    uint32_t lastRedraw = 0;
    while (true) {
        processReconPacket();
        updateSweep();

        if (millis() - lastHeartbeat > HEARTBEAT_MS) {
            lastHeartbeat = millis();
            Serial.printf(
                "[LoRaRecon] listening... packets=%lu uptime=%lus\n", (unsigned long)reconPacketCount,
                (unsigned long)(millis() / 1000)
            );
        }

        if (millis() - lastRedraw > REDRAW_MS) {
            lastRedraw = millis();
            tft.fillRect(0, tftHeight / 2 + 4, tftWidth, 60, TFT_BLACK);
            tft.setTextColor(TFT_WHITE, TFT_BLACK);

            char sweepLine[48];
            if (sweepStage == SweepStage::Rx2) {
                snprintf(sweepLine, sizeof(sweepLine), "RX2  %.3fMHz  SF%u", RX2_FREQ_MHZ, RX2_SF);
            } else {
                snprintf(
                    sweepLine, sizeof(sweepLine), "CH %u/%u  %.3fMHz  SF%u%s", (unsigned)(sweepChannelIdx + 1),
                    (unsigned)EU868_CHANNEL_COUNT, EU868_CHANNELS_MHZ[sweepChannelIdx],
                    SF_DWELL_TABLE[lockEnabled ? lockedSfIdx : sweepSfIdx].sf, lockEnabled ? " LOCK" : ""
                );
            }
            tft.drawCentreString(sweepLine, tftWidth / 2, tftHeight / 2 + 6, 1);

            char countLine[24];
            snprintf(countLine, sizeof(countLine), "Packets: %lu", (unsigned long)reconPacketCount);
            tft.drawCentreString(countLine, tftWidth / 2, tftHeight / 2 + 18, 1);
            tft.drawCentreString(lastFrameSummary, tftWidth / 2, tftHeight / 2 + 30, 1);
        }

        if (check(SelPress)) toggleLock();
        if (check(EscPress)) break;
        delay(5);
    }

    stopReconRadio();
    Serial.println("[LoRaRecon] stopped, exiting");
}
#endif
