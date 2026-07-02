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
#include <vector>

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

// Decoded-traffic counters.
uint32_t meshTextCount = 0;
bool selfTestPassed = false;
bool needsRedraw = true;

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

// --- UI state (Phase 6) ---
enum class View { Conversation, Nodes };
View view = View::Conversation;
bool viewFullClear = true; // fillScreen once per view entry, then only sub-regions

struct ConvMsg {
    uint32_t from;
    bool mine;
    String text;
    float rssi;
    float snr;
    uint32_t atMs;
};
std::vector<ConvMsg> convo; // oldest at front, newest at back
constexpr size_t MAX_CONVO = 60;
int convScroll = 0; // lines scrolled up from the bottom (0 = pinned to newest)

struct NodeEnt {
    uint32_t id;
    uint32_t lastSeenMs;
    float rssi;
    float snr;
    uint32_t count;
};
std::vector<NodeEnt> nodes;
constexpr size_t MAX_NODES = 48;
int nodesCursor = 0;
int nodesTop = 0;

// Render caches for flicker-free diffed drawing: a row/line is only repainted
// when its text or colours actually change (mirrors the recon fix). Reset by
// resetRenderCache() on every view entry (viewFullClear).
constexpr int MAX_BODY_ROWS = 24;
String bodyTextCache[MAX_BODY_ROWS];
uint16_t bodyFgCache[MAX_BODY_ROWS];
uint16_t bodyBgCache[MAX_BODY_ROWS];
String chromeLineCache[2];
String footerCache;

void resetRenderCache() {
    for (int i = 0; i < MAX_BODY_ROWS; i++) {
        bodyTextCache[i] = "\x01"; // sentinel: guarantees first draw differs
        bodyFgCache[i] = 0xDEAD;
        bodyBgCache[i] = 0xDEAD;
    }
    chromeLineCache[0] = "\x01";
    chromeLineCache[1] = "\x01";
    footerCache = "\x01";
}

// Records/updates a heard node from any decoded frame's `from` field.
void touchNode(uint32_t id, float rssi, float snr) {
    for (auto &n : nodes) {
        if (n.id == id) {
            n.lastSeenMs = millis();
            n.rssi = rssi;
            n.snr = snr;
            n.count++;
            return;
        }
    }
    if (nodes.size() >= MAX_NODES) nodes.erase(nodes.begin()); // evict oldest-inserted
    nodes.push_back({id, millis(), rssi, snr, 1});
}

void addConvMsg(uint32_t from, bool mine, const String &text, float rssi, float snr) {
    ConvMsg m;
    m.from = from;
    m.mine = mine;
    m.text = text;
    m.rssi = rssi;
    m.snr = snr;
    m.atMs = millis();
    convo.push_back(m);
    if (convo.size() > MAX_CONVO) convo.erase(convo.begin());
    if (convScroll != 0) convScroll++; // keep the same messages in view when not pinned to bottom
}

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
        (unsigned)hdr.to, (unsigned)hdr.from, (unsigned)hdr.id, hdr.flags, hdr.channel, hdr.hopLimit(),
        hdr.hopStart(), hdr.next_hop, hdr.relay_node
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
    Serial.printf("[Meshtastic]   decoded portnum=%u (%s) payloadLen=%u\n", (unsigned)dm.portnum,
                  portName(dm.portnum).c_str(), (unsigned)dm.payloadLen);

    // Any successfully-decoded frame proves a heard node on this channel.
    touchNode(hdr.from, rssi, snr);

    if (dm.portnum == meshtastic::TEXT_MESSAGE_APP) {
        String text;
        text.reserve(dm.payloadLen + 1);
        for (size_t i = 0; i < dm.payloadLen; i++) text += (char)dm.payload[i];
        meshTextCount++;
        addConvMsg(hdr.from, false, text, rssi, snr);
        if (view == View::Conversation) needsRedraw = true;
        Serial.printf(
            "[Meshtastic]   >>> TEXT from !%08x: \"%s\" (rssi=%.0fdBm snr=%.1fdB)\n", (unsigned)hdr.from,
            text.c_str(), rssi, snr
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
            (unsigned)airMs, (unsigned)dutyCycle.usedMs(now), (unsigned)dutyCycle.budgetMs,
            (unsigned)lastTxBlockedWaitS
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
    // Show our own sent line in the conversation view.
    addConvMsg(ourNodeId, true, text, 0, 0);
    needsRedraw = true;
    Serial.printf(
        "[Meshtastic] TX #%lu id=0x%08x len=%u airtime=%ums used=%ums/%ums \"%s\"\n",
        (unsigned long)meshTxCount, (unsigned)id, (unsigned)frameLen, (unsigned)airMs,
        (unsigned)dutyCycle.usedMs(now), (unsigned)dutyCycle.budgetMs, text.c_str()
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

// ---------------------------------------------------------------------------
// UI layout (320x240, FP font). Two persistent views (Conversation / Nodes)
// plus a modal compose via keyboard(). Chrome + footer are shared. Redraws
// touch only sub-regions (never a periodic fillScreen) to stay flicker-free;
// a full clear happens once per view entry via viewFullClear.
// ---------------------------------------------------------------------------
constexpr int CHROME_H = 30;        // two chrome rows + separator
constexpr int FOOTER_H = 12;        // one footer row
constexpr int ROW_H = 11;           // body line height (FP)

String shortText(const String &s, size_t maxChars) {
    if (s.length() <= maxChars) return s;
    return s.substring(0, maxChars);
}

// Draw one body row only if its text/colours changed since last time (diffed to
// avoid flicker). `slot` indexes the cache; row is cleared to bg then painted.
void drawBodyRow(int slot, int y, const String &text, uint16_t fg, uint16_t bg) {
    if (slot < 0 || slot >= MAX_BODY_ROWS) return;
    if (bodyTextCache[slot] == text && bodyFgCache[slot] == fg && bodyBgCache[slot] == bg) return;
    bodyTextCache[slot] = text;
    bodyFgCache[slot] = fg;
    bodyBgCache[slot] = bg;
    tft.fillRect(0, y - 1, tftWidth, ROW_H, bg);
    tft.setTextSize(FP);
    tft.setTextColor(fg, bg);
    tft.drawString(text, 4, y);
}

// Shared top chrome, diffed per line so the 1 Hz duty/age refresh doesn't flash.
void drawChrome() {
    tft.setTextSize(FP);
    char line[80];

    snprintf(line, sizeof(line), "Meshtastic LF  !%08x", (unsigned)ourNodeId);
    if (chromeLineCache[0] != line) {
        chromeLineCache[0] = line;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(line, 4, 2);
    }

    uint32_t used = dutyCycle.usedMs(millis());
    int pct = dutyCycle.budgetMs ? (int)((used * 100) / dutyCycle.budgetMs) : 0;
    const char *st = txInProgress ? "TX>>" : (lastTxBlocked ? "BLK" : "RX");
    snprintf(line, sizeof(line), "LongFast 869.5  duty:%d%%  TX:%lu  %s", pct, (unsigned long)meshTxCount, st);
    if (chromeLineCache[1] != line) {
        chromeLineCache[1] = line;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(
            txInProgress ? TFT_ORANGE : (lastTxBlocked || pct >= 100 ? TFT_RED : TFT_GREEN), TFT_BLACK
        );
        tft.drawString(line, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}

void drawFooter(const String &hint) {
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}

// Screen A - conversation. Newest at bottom; own messages ">> ..." in priColor,
// others "!from: ..." in white with an RF tag. convScroll pages up from bottom.
void drawConversation() {
    if (viewFullClear) {
        tft.fillScreen(TFT_BLACK);
        resetRenderCache();
        viewFullClear = false;
    }
    drawChrome();

    int bodyTop = CHROME_H;
    int bodyH = tftHeight - CHROME_H - FOOTER_H;
    int rows = bodyH / ROW_H;
    if (rows > MAX_BODY_ROWS) rows = MAX_BODY_ROWS;

    int total = (int)convo.size();
    int end = total - convScroll; // one past last visible (bottom-anchored)
    if (end > total) end = total;
    if (end < 0) end = 0;
    int start = end - rows;
    if (start < 0) start = 0;

    char meta[64];
    // Each of the `rows` fixed slots either shows a message or is blanked, so a
    // scrolled-away line is cleared (not left stale) but only when it changed.
    for (int slot = 0; slot < rows; slot++) {
        int y = bodyTop + slot * ROW_H;
        int i = start + slot;
        if (i < end && i < total) {
            const ConvMsg &m = convo[i];
            if (m.mine) {
                drawBodyRow(slot, y, shortText(">> " + m.text, 50), bruceConfig.priColor, TFT_BLACK);
            } else {
                snprintf(meta, sizeof(meta), "!%08x: ", (unsigned)m.from);
                String tag = " ";
                {
                    char rf[24];
                    snprintf(rf, sizeof(rf), "  %.0f/%.0f", m.rssi, m.snr);
                    tag = rf;
                }
                drawBodyRow(slot, y, shortText(String(meta) + m.text, 40) + tag, TFT_WHITE, TFT_BLACK);
            }
        } else if (total == 0 && slot == 0) {
            drawBodyRow(slot, y, "  (no messages yet - SEL to compose)", TFT_DARKGREY, TFT_BLACK);
        } else {
            drawBodyRow(slot, y, "", TFT_WHITE, TFT_BLACK); // blank unused slot
        }
    }

    drawFooter(convScroll > 0 ? "SEL compose  n nodes  ^v scroll(older)  <-exit"
                              : "SEL compose  n nodes  ^ scroll  <-exit");
}

// Screen C - nodes heard on the channel. node-ID / last RSSI-SNR / count / age.
void drawNodes() {
    if (viewFullClear) {
        tft.fillScreen(TFT_BLACK);
        resetRenderCache();
        viewFullClear = false;
    }
    drawChrome();

    int bodyTop = CHROME_H;
    int bodyH = tftHeight - CHROME_H - FOOTER_H;
    int rows = bodyH / ROW_H;
    if (rows > MAX_BODY_ROWS) rows = MAX_BODY_ROWS;

    if (nodesCursor < nodesTop) nodesTop = nodesCursor;
    if (nodesCursor >= nodesTop + rows) nodesTop = nodesCursor - rows + 1;

    char line[80];
    for (int slot = 0; slot < rows; slot++) {
        int y = bodyTop + slot * ROW_H;
        int i = nodesTop + slot;
        if (i < (int)nodes.size()) {
            const NodeEnt &n = nodes[i];
            bool sel = (i == nodesCursor);
            uint32_t ageS = (millis() - n.lastSeenMs) / 1000;
            snprintf(
                line, sizeof(line), "!%08x  %.0f/%.0f  x%lu  %lus", (unsigned)n.id, n.rssi, n.snr,
                (unsigned long)n.count, (unsigned long)ageS
            );
            drawBodyRow(slot, y, line, sel ? TFT_BLACK : TFT_WHITE, sel ? bruceConfig.priColor : TFT_BLACK);
        } else if (nodes.empty() && slot == 0) {
            drawBodyRow(slot, y, "  (no nodes heard yet)", TFT_DARKGREY, TFT_BLACK);
        } else {
            drawBodyRow(slot, y, "", TFT_WHITE, TFT_BLACK);
        }
    }

    char cnt[48];
    snprintf(cnt, sizeof(cnt), "%d nodes  ^v move  n/<- back", (int)nodes.size());
    drawFooter(cnt);
}

void drawCurrentView() {
    if (view == View::Conversation) drawConversation();
    else drawNodes();
}

// Modal compose using Bruce's on-device QWERTY keyboard, then encrypt+send.
void composeAndSend() {
    String text = keyboard("", 230, "Type message:");
    viewFullClear = true; // keyboard took the whole screen
    if (text.length() == 0 || text == "\x1B") {
        needsRedraw = true;
        return;
    }
    sendMeshText(text); // duty-cycle guarded inside; appends to convo on success
    needsRedraw = true;
}

void handleConversationInput() {
    if (check(PrevPress) || check(UpPress)) {
        int maxScroll = (int)convo.size();
        if (convScroll < maxScroll) convScroll++;
        needsRedraw = true;
    }
    if (check(NextPress) || check(DownPress)) {
        if (convScroll > 0) convScroll--;
        needsRedraw = true;
    }
    if (check(SelPress)) {
        composeAndSend();
    }
    static uint32_t lastShortcut = 0;
    if (millis() - lastShortcut > 80) {
        lastShortcut = millis();
        char c = checkLetterShortcutPress();
        if (c == 'c' || c == 'C') composeAndSend();
        else if (c == 'n' || c == 'N') {
            view = View::Nodes;
            nodesCursor = 0;
            nodesTop = 0;
            viewFullClear = true;
            needsRedraw = true;
        }
    }
}

void handleNodesInput() {
    if (check(PrevPress) || check(UpPress)) {
        if (nodesCursor > 0) nodesCursor--;
        needsRedraw = true;
    }
    if (check(NextPress) || check(DownPress)) {
        if (nodesCursor < (int)nodes.size() - 1) nodesCursor++;
        needsRedraw = true;
    }
    static uint32_t lastShortcut = 0;
    if (millis() - lastShortcut > 80) {
        lastShortcut = millis();
        char c = checkLetterShortcutPress();
        if (c == 'n' || c == 'N') {
            view = View::Conversation;
            viewFullClear = true;
            needsRedraw = true;
        }
    }
}

} // namespace

void meshtasticChannel() {
    Serial.println("[Meshtastic] opening (LongFast / EU868)");
    meshRxCount = 0;
    lastRxLen = 0;
    meshTextCount = 0;
    meshTxCount = 0;
    lastTxBlocked = false;
    dutyCycle.reset();

    // Expand the LongFast default channel key (PSK index 1) once.
    meshtastic::expandPsk(1, meshKey, meshKeyLen);
    ourNodeId = deriveNodeId();
    Serial.printf("[Meshtastic] our node-ID: !%08x\n", (unsigned)ourNodeId);

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

    view = View::Conversation;
    convo.clear();
    nodes.clear();
    convScroll = 0;
    nodesCursor = 0;
    nodesTop = 0;
    viewFullClear = true;
    needsRedraw = true;
    drawCurrentView();

    uint32_t lastHeartbeat = millis();
    uint32_t lastChromeTick = millis();

    Serial.println("[Meshtastic] type a line on serial to transmit it as a text message");
    String serialLine;

    while (true) {
        processMeshRx();

        // Serial-triggered TX: lets sending be triggered/observed over USB, in
        // addition to the on-screen compose keyboard. A full line = one message.
        while (Serial.available()) {
            char c = (char)Serial.read();
            if (c == '\n' || c == '\r') {
                serialLine.trim();
                if (serialLine.length() > 0) {
                    Serial.printf("[Meshtastic] serial compose: \"%s\"\n", serialLine.c_str());
                    sendMeshText(serialLine);
                    needsRedraw = true;
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

        // Refresh once a second so the duty-cycle % and node ages stay current
        // (sub-region redraw only, never a full-screen fill -> no flicker).
        if (millis() - lastChromeTick > 1000) {
            lastChromeTick = millis();
            needsRedraw = true;
        }

        // Input (per view). Backspace exits from Conversation, or backs out of
        // Nodes into Conversation.
        if (view == View::Conversation) {
            if (check(EscPress)) break;
            handleConversationInput();
        } else {
            if (check(EscPress)) {
                view = View::Conversation;
                viewFullClear = true;
                needsRedraw = true;
            } else {
                handleNodesInput();
            }
        }

        if (needsRedraw) {
            needsRedraw = false;
            drawCurrentView();
        }

        delay(5);
    }

    stopMeshRadio();
    Serial.println("[Meshtastic] stopped, exiting");
}
#endif
