#if !defined(LITE_VERSION)
#include "Meshtastic.h"
#include "MeshtasticCodec.h"
#include "core/configPins.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "modules/lora/LoRaRF.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <esp_system.h>
#include <globals.h>

extern BruceConfigPins bruceConfigPins;

// ---------------------------------------------------------------------------
// Meshtastic LongFast text client.
//
// Phase 3: independent SX1262 brought up in the exact LongFast / EU_868 config
// and put into interrupt-driven continuous RX. Every received frame is logged
// raw (hex + RF metrics) to serial; a heartbeat proves the loop is alive with
// no traffic. Decrypt/protobuf (Phase 4) and TX (Phase 5) come next; this file
// does NOT transmit yet.
//
// All radio constants are anchored to Meshtastic firmware v2.7.26 - see
// docs/meshtastic-notes.md for the source lines each value came from.
// ---------------------------------------------------------------------------

namespace {

// --- LongFast preset, region EU_868 -------------------------------------
constexpr float MESH_FREQ_MHZ = 869.525f;    // getFreq(): 869.4 + 250/2000 + 0
constexpr float MESH_BW_KHZ = 250.0f;        // LONG_FAST bandwidth
constexpr uint8_t MESH_SF = 11;              // LONG_FAST spreading factor
constexpr uint8_t MESH_CR = 5;               // LONG_FAST coding rate 4/5
constexpr uint8_t MESH_SYNC_WORD = 0x2b;     // RadioLibInterface.h syncWord
constexpr size_t MESH_PREAMBLE = 16;         // RadioInterface.h preambleLength
constexpr int8_t MESH_TX_POWER_DBM = 22;     // SX1262 max; EU868 region cap 27dBm

constexpr uint32_t HEARTBEAT_MS = 3000;

SPIClass *meshSpi = nullptr;
Module *meshModule = nullptr;
SX1262 *meshRadio = nullptr;
volatile bool meshIrqEnabled = true;
volatile bool meshPacketReceived = false;
uint32_t meshRxCount = 0;

// Last-RX snapshot for the on-screen status (full UI is Phase 6).
size_t lastRxLen = 0;
float lastRxRssi = 0;
float lastRxSnr = 0;
uint32_t lastRxAtMs = 0;

// Decoded-traffic snapshot (Phase 4). Full conversation/nodes store is Phase 6.
uint32_t meshTextCount = 0;
String lastText;
uint32_t lastTextFrom = 0;
bool selfTestPassed = false;

// LongFast default-channel key, expanded once at start.
uint8_t meshKey[16];
size_t meshKeyLen = 0;

// TX state (Phase 5).
uint32_t ourNodeId = 0;              // stable 32-bit node-ID (from MAC)
meshtastic::DutyCycle dutyCycle;     // EU868 10% airtime limiter
uint32_t meshTxCount = 0;
uint32_t lastTxAtMs = 0;
volatile bool txInProgress = false;  // true only while transmit() is running
bool lastTxBlocked = false;          // last send attempt was refused by the guard
uint32_t lastTxBlockedWaitS = 0;

void IRAM_ATTR onMeshPacket() {
    if (!meshIrqEnabled) return;
    meshPacketReceived = true;
}

void clearMeshRadio() {
    if (meshRadio) {
        delete meshRadio;
        meshRadio = nullptr;
    }
    if (meshModule) {
        delete meshModule;
        meshModule = nullptr;
    }
}

String toHex(const uint8_t *data, size_t len) {
    String hex;
    hex.reserve(len * 2);
    char b[3];
    for (size_t i = 0; i < len; i++) {
        snprintf(b, sizeof(b), "%02X", data[i]);
        hex += b;
    }
    return hex;
}

// Brings up our own independent SX1262 (separate from the chat/recon radios)
// in the LongFast config and starts continuous RX. Returns false on any init
// error. Never calls a transmit API.
bool startMeshRadio() {
    meshPacketReceived = false;
    meshIrqEnabled = true;

    if (getLoraCsPin() == GPIO_NUM_NC || bruceConfigPins.LoRa_bus.mosi == GPIO_NUM_NC ||
        bruceConfigPins.LoRa_bus.miso == GPIO_NUM_NC || bruceConfigPins.LoRa_bus.sck == GPIO_NUM_NC) {
        Serial.println("[Meshtastic] LoRa pins not configured!");
        displayError("LoRa pins not configured!", true);
        return false;
    }
    const int irqPin = getLoraIrqPin();
    if (irqPin == GPIO_NUM_NC) {
        Serial.println("[Meshtastic] LoRa IRQ pin not configured!");
        displayError("LoRa IRQ pin not configured!", true);
        return false;
    }
    const int busyPin = getLoraBusyPin();
    if (busyPin == GPIO_NUM_NC) { Serial.println("[Meshtastic] Warning: SX1262 BUSY pin not configured"); }

    meshSpi = selectLoraSPIBus();
    clearMeshRadio();
    meshModule = new Module(getLoraCsPin(), irqPin, getLoraResetPin(), busyPin, *meshSpi);
    meshRadio = new SX1262(meshModule);

    int state = meshRadio->begin(MESH_FREQ_MHZ);
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setBandwidth(MESH_BW_KHZ);
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setSpreadingFactor(MESH_SF);
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setCodingRate(MESH_CR);
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setPreambleLength(MESH_PREAMBLE);
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setSyncWord(MESH_SYNC_WORD);
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setCRC(1); // Meshtastic: CRC on
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->invertIQ(false); // standard IQ
    // Cap PA now so the radio is fully configured for the Phase-5 TX path; this
    // only sets the ramp, it does not transmit.
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->setOutputPower(MESH_TX_POWER_DBM);
    if (state == RADIOLIB_ERR_NONE) { meshRadio->setDio1Action(onMeshPacket); }
    if (state == RADIOLIB_ERR_NONE) state = meshRadio->startReceive();

    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[Meshtastic] Radio init failed! Err %d\n", state);
        displayError("Meshtastic radio init failed", true);
        clearMeshRadio();
        return false;
    }

    Serial.printf(
        "[Meshtastic] Radio up: %.3fMHz SF%u BW%.0fkHz CR4/%u sync=0x%02X preamble=%u CRC=on "
        "pwr=%ddBm (RX active, no TX yet)\n",
        MESH_FREQ_MHZ, MESH_SF, MESH_BW_KHZ, MESH_CR, MESH_SYNC_WORD, (unsigned)MESH_PREAMBLE,
        MESH_TX_POWER_DBM
    );
    return true;
}

void stopMeshRadio() {
    if (meshRadio) meshRadio->standby();
    clearMeshRadio();
}

// Returns a human label for a portnum (text ones surfaced, others by number).
String portName(uint32_t portnum) {
    switch (portnum) {
    case meshtastic::TEXT_MESSAGE_APP: return "TEXT";
    case meshtastic::POSITION_APP: return "POSITION";
    case meshtastic::NODEINFO_APP: return "NODEINFO";
    case meshtastic::ROUTING_APP: return "ROUTING";
    case meshtastic::UNKNOWN_APP: return "UNKNOWN";
    default: return "port#" + String(portnum);
    }
}

// Phase 4 decode path: header parse -> channel-hash filter -> AES-CTR decrypt
// with the LongFast key -> minimal Data protobuf decode -> surface text.
// `buf`/`len` is the full on-air frame (header + ciphertext).
void decodeMeshFrame(const uint8_t *buf, size_t len, float rssi, float snr) {
    meshtastic::PacketHeader hdr;
    if (!meshtastic::unpackHeader(buf, len, hdr)) {
        Serial.println("[Meshtastic]   frame too short for header, skipped");
        return;
    }
    Serial.printf(
        "[Meshtastic]   hdr to=!%08x from=!%08x id=0x%08x flags=0x%02x ch=0x%02x hop=%u/%u nh=%u rn=%u\n",
        hdr.to, hdr.from, hdr.id, hdr.flags, hdr.channel, hdr.hopLimit(), hdr.hopStart(), hdr.next_hop,
        hdr.relay_node
    );

    if (hdr.channel != meshtastic::LONGFAST_CHANNEL_HASH) {
        Serial.printf(
            "[Meshtastic]   channel 0x%02x != LongFast 0x%02x - not our channel, skipped\n", hdr.channel,
            meshtastic::LONGFAST_CHANNEL_HASH
        );
        return;
    }

    size_t ctLen = len - meshtastic::HEADER_LEN;
    if (ctLen == 0 || ctLen > meshtastic::MAX_PLAINTEXT) {
        Serial.println("[Meshtastic]   empty/oversized ciphertext, skipped");
        return;
    }

    uint8_t pt[meshtastic::MAX_PLAINTEXT];
    memcpy(pt, buf + meshtastic::HEADER_LEN, ctLen);
    uint8_t nonce[16];
    meshtastic::initNonce(hdr.from, hdr.id, nonce);
    meshtastic::aesCtrCrypt(meshKey, nonce, pt, ctLen);

    meshtastic::DataMsg dm;
    if (!meshtastic::decodeData(pt, ctLen, dm)) {
        Serial.println("[Meshtastic]   decrypt->protobuf undecodable (foreign key or non-Data), ignored");
        return;
    }
    Serial.printf("[Meshtastic]   decoded portnum=%u (%s) payloadLen=%u\n", dm.portnum,
                  portName(dm.portnum).c_str(), (unsigned)dm.payloadLen);

    if (dm.portnum == meshtastic::TEXT_MESSAGE_APP) {
        String text;
        text.reserve(dm.payloadLen + 1);
        for (size_t i = 0; i < dm.payloadLen; i++) text += (char)dm.payload[i];
        meshTextCount++;
        lastText = text;
        lastTextFrom = hdr.from;
        Serial.printf(
            "[Meshtastic]   >>> TEXT from !%08x: \"%s\" (rssi=%.0fdBm snr=%.1fdB)\n", hdr.from, text.c_str(),
            rssi, snr
        );
    }
}

// Stable 32-bit node-ID from the ESP32 efuse MAC (low 4 bytes, Meshtastic-style).
// MAC is fixed per device so this is stable across boots without extra storage.
uint32_t deriveNodeId() {
    uint64_t mac = ESP.getEfuseMac();
    uint32_t id = (uint32_t)(mac & 0xFFFFFFFFu);
    if (id == 0 || id == meshtastic::BROADCAST_ADDR) {
        id = 0x0BACE000u | (uint32_t)((mac >> 32) & 0xFFF); // avoid reserved/broadcast
    }
    return id;
}

// Compose -> encode Data -> encrypt -> frame -> duty-cycle guard -> transmit ->
// re-arm RX. This is the ONLY transmit path; it runs only on explicit user
// action (compose/send or a serial trigger), never in a loop. Returns true on
// a successful transmit; false if empty, encode-failed, blocked, or radio error.
bool sendMeshText(const String &text) {
    if (!meshRadio || text.length() == 0) return false;

    uint8_t data[meshtastic::MAX_PLAINTEXT];
    size_t dataLen =
        meshtastic::encodeData(meshtastic::TEXT_MESSAGE_APP, (const uint8_t *)text.c_str(),
                               text.length(), data, sizeof(data));
    if (dataLen == 0) {
        Serial.println("[Meshtastic] TX: message too long to encode");
        return false;
    }

    uint32_t id = esp_random();
    if (id == 0) id = 1; // id 0 is reserved / a poor nonce input

    uint8_t nonce[16];
    meshtastic::initNonce(ourNodeId, id, nonce);
    meshtastic::aesCtrCrypt(meshKey, nonce, data, dataLen);

    uint8_t frame[meshtastic::HEADER_LEN + meshtastic::MAX_PLAINTEXT];
    meshtastic::PacketHeader h;
    h.to = meshtastic::BROADCAST_ADDR;
    h.from = ourNodeId;
    h.id = id;
    h.flags = meshtastic::PacketHeader::makeFlags(3, false, 3); // hop_limit=3, hop_start=3
    h.channel = meshtastic::LONGFAST_CHANNEL_HASH;
    meshtastic::packHeader(h, frame);
    memcpy(frame + meshtastic::HEADER_LEN, data, dataLen);
    size_t frameLen = meshtastic::HEADER_LEN + dataLen;

    // --- Mandatory EU868 10% duty-cycle guard (non-negotiable, always in path) ---
    uint32_t now = millis();
    uint32_t airMs = meshRadio->getTimeOnAir(frameLen) / 1000;
    if (dutyCycle.wouldExceed(now, airMs)) {
        uint32_t waitMs = dutyCycle.msUntilAvailable(now, airMs);
        lastTxBlocked = true;
        lastTxBlockedWaitS = (waitMs + 999) / 1000;
        Serial.printf(
            "[Meshtastic] TX BLOCKED by duty cycle: pkt=%ums used=%ums/%ums budget, retry in ~%us\n",
            airMs, dutyCycle.usedMs(now), dutyCycle.budgetMs, lastTxBlockedWaitS
        );
        return false;
    }
    lastTxBlocked = false;

    // --- Transmit (half-duplex: mute RX IRQ, send, re-arm RX) ---
    txInProgress = true;
    meshIrqEnabled = false;
    int st = meshRadio->transmit(frame, frameLen);
    meshRadio->startReceive();
    meshIrqEnabled = true;
    txInProgress = false;

    if (st != RADIOLIB_ERR_NONE) {
        Serial.printf("[Meshtastic] TX failed: %d\n", st);
        return false;
    }

    dutyCycle.record(now, airMs);
    meshTxCount++;
    lastTxAtMs = now;
    // Show our own sent line in the local view too.
    meshTextCount++;
    lastText = String("(me) ") + text;
    lastTextFrom = ourNodeId;
    Serial.printf(
        "[Meshtastic] TX #%lu id=0x%08x len=%u airtime=%ums used=%ums/%ums \"%s\"\n",
        (unsigned long)meshTxCount, id, (unsigned)frameLen, airMs, dutyCycle.usedMs(now),
        dutyCycle.budgetMs, text.c_str()
    );
    return true;
}

// Reads one pending frame, logs it raw with RF metrics, decodes it, re-arms RX.
void processMeshRx() {
    if (!meshPacketReceived || !meshRadio) return;
    meshIrqEnabled = false;
    meshPacketReceived = false;

    size_t len = meshRadio->getPacketLength();
    if (len == 0 || len > 255) {
        meshRadio->startReceive();
        meshIrqEnabled = true;
        return;
    }

    uint8_t buf[255];
    int state = meshRadio->readData(buf, len);
    bool crcOk = (state == RADIOLIB_ERR_NONE);
    bool crcMismatch = (state == RADIOLIB_ERR_CRC_MISMATCH);

    if (crcOk || crcMismatch) {
        float rssi = meshRadio->getRSSI();
        float snr = meshRadio->getSNR();
        float airtimeMs = meshRadio->getTimeOnAir(len) / 1000.0f;
        meshRxCount++;
        lastRxLen = len;
        lastRxRssi = rssi;
        lastRxSnr = snr;
        lastRxAtMs = millis();
        Serial.printf(
            "[Meshtastic] RX #%lu len=%u rssi=%.1fdBm snr=%.1fdB airtime=%.1fms crc=%s hex=%s\n",
            (unsigned long)meshRxCount, (unsigned)len, rssi, snr, airtimeMs, crcOk ? "OK" : "MISMATCH",
            toHex(buf, len).c_str()
        );
        decodeMeshFrame(buf, len, rssi, snr);
    } else {
        Serial.printf("[Meshtastic] RX read failed: %d\n", state);
    }

    meshRadio->startReceive();
    meshIrqEnabled = true;
}

void drawStatusScreen() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
    tft.drawCentreString("Meshtastic LF", tftWidth / 2, 8, 1);

    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    char line[72];
    int y = 30;
    tft.drawString("LongFast  EU868  869.525 MHz", 6, y);
    y += 12;
    tft.drawString("SF11 / BW250 / CR4:5  sync 0x2b", 6, y);
    y += 12;
    snprintf(line, sizeof(line), "node !%08x", ourNodeId);
    tft.drawString(line, 6, y);
    y += 12;
    // Duty-cycle budget indicator.
    uint32_t used = dutyCycle.usedMs(millis());
    int pct = dutyCycle.budgetMs ? (int)((used * 100) / dutyCycle.budgetMs) : 0;
    snprintf(line, sizeof(line), "duty: %d%% used  TX:%lu", pct, (unsigned long)meshTxCount);
    tft.setTextColor(pct >= 100 ? TFT_RED : TFT_WHITE, TFT_BLACK);
    tft.drawString(line, 6, y);
    y += 14;
    if (txInProgress) {
        tft.setTextColor(TFT_ORANGE, TFT_BLACK);
        tft.drawString(">> TRANSMITTING <<", 6, y);
    } else if (lastTxBlocked) {
        tft.setTextColor(TFT_RED, TFT_BLACK);
        snprintf(line, sizeof(line), "TX blocked (retry ~%lus)", (unsigned long)lastTxBlockedWaitS);
        tft.drawString(line, 6, y);
    } else {
        tft.setTextColor(TFT_GREEN, TFT_BLACK);
        tft.drawString("Listening...", 6, y);
    }
    y += 14;
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    snprintf(line, sizeof(line), "Frames heard: %lu", (unsigned long)meshRxCount);
    tft.drawString(line, 6, y);
    y += 12;
    if (meshRxCount > 0) {
        snprintf(
            line, sizeof(line), "last: len=%u %.0fdBm %.1fdB %lus ago", (unsigned)lastRxLen, lastRxRssi,
            lastRxSnr, (unsigned long)((millis() - lastRxAtMs) / 1000)
        );
        tft.drawString(line, 6, y);
    }
    y += 16;
    snprintf(line, sizeof(line), "Text msgs: %lu", (unsigned long)meshTextCount);
    tft.drawString(line, 6, y);
    if (meshTextCount > 0) {
        y += 12;
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        char t[64];
        snprintf(t, sizeof(t), "!%08x: %s", lastTextFrom, lastText.c_str());
        tft.drawString(String(t).substring(0, 40), 6, y);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
    }

    tft.setTextColor(selfTestPassed ? TFT_GREEN : TFT_RED, TFT_BLACK);
    tft.drawString(selfTestPassed ? "self-test: OK" : "self-test: FAIL", 6, tftHeight - 28);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawCentreString("Backspace to exit", tftWidth / 2, tftHeight - 16, 1);
}

} // namespace

void meshtasticChannel() {
    Serial.println("[Meshtastic] opening (LongFast / EU868)");
    meshRxCount = 0;
    lastRxLen = 0;
    meshTextCount = 0;
    lastText = "";
    lastTextFrom = 0;
    meshTxCount = 0;
    lastTxBlocked = false;
    dutyCycle.reset();

    // Expand the LongFast default channel key (PSK index 1) once.
    meshtastic::expandPsk(1, meshKey, meshKeyLen);
    ourNodeId = deriveNodeId();
    Serial.printf("[Meshtastic] our node-ID: !%08x\n", ourNodeId);

    // Deterministic codec/crypto self-test (Appendix A) on every open, so a
    // regression is always visible before any radio traffic (mirrors recon).
    selfTestPassed = meshtastic::runMeshtasticSelfTest();

    tft.fillScreen(TFT_BLACK);
    tft.setTextSize(FM);
    tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
    tft.drawCentreString("Meshtastic LF", tftWidth / 2, 8, 1);
    tft.setTextSize(FP);
    tft.setTextColor(selfTestPassed ? TFT_GREEN : TFT_RED, TFT_BLACK);
    tft.drawCentreString(
        selfTestPassed ? "self-test: OK" : "self-test: FAILED", tftWidth / 2, tftHeight / 2 - 10, 1
    );
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.drawCentreString("starting radio...", tftWidth / 2, tftHeight / 2 + 6, 1);
    delay(500);

    if (!startMeshRadio()) {
        while (true) {
            if (check(EscPress)) return;
            delay(20);
        }
    }

    drawStatusScreen();
    uint32_t lastHeartbeat = millis();
    uint32_t seenAtLastDraw = 0;

    Serial.println("[Meshtastic] type a line on serial to transmit it as a text message");
    String serialLine;

    while (true) {
        processMeshRx();

        // Serial-triggered TX: lets sending be triggered/observed over USB (the
        // on-screen compose keyboard is Phase 6). A full line = one text message.
        while (Serial.available()) {
            char c = (char)Serial.read();
            if (c == '\n' || c == '\r') {
                serialLine.trim();
                if (serialLine.length() > 0) {
                    Serial.printf("[Meshtastic] serial compose: \"%s\"\n", serialLine.c_str());
                    sendMeshText(serialLine);
                    drawStatusScreen();
                }
                serialLine = "";
            } else if (serialLine.length() < 230) {
                serialLine += c;
            }
        }

        if (millis() - lastHeartbeat > HEARTBEAT_MS) {
            lastHeartbeat = millis();
            Serial.printf(
                "[Meshtastic] listening... frames=%lu tx=%lu uptime=%lus\n", (unsigned long)meshRxCount,
                (unsigned long)meshTxCount, (unsigned long)(millis() / 1000)
            );
        }

        // Only redraw when a new frame actually arrives - no periodic fillScreen,
        // so an idle (no-peer) screen stays flicker-free. Full diffed UI is Phase 6.
        if (meshRxCount != seenAtLastDraw) {
            seenAtLastDraw = meshRxCount;
            drawStatusScreen();
        }

        if (check(EscPress)) break;
        delay(5);
    }

    stopMeshRadio();
    Serial.println("[Meshtastic] stopped, exiting");
}
#endif
