#if !defined(LITE_VERSION)
#include "Meshtastic.h"
#include "MeshtasticCodec.h"
#include "core/configPins.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
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

// Self-NodeInfo broadcast so peers show a name instead of a bare !id. Names are
// derived from the node-ID at open (no extra config/storage needed).
char meshLongName[24] = {0};
char meshShortName[8] = {0};
constexpr uint32_t NODEINFO_INTERVAL_MS = 30UL * 60 * 1000; // re-announce every 30 min
constexpr uint32_t NODEINFO_FIRST_MS = 8000;                // first announce ~8s after open
uint32_t nextNodeInfoAtMs = 0;

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
    String clk; // "HH:MM:SS" wall-clock at arrival, or "+HH:MM:SS" uptime if clock unset
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
    String name; // short name from NODEINFO, if heard (Phase 8)
};
std::vector<NodeEnt> nodes;
constexpr size_t MAX_NODES = 48;
int nodesCursor = 0;
int nodesTop = 0;

// SD conversation logging (Phase 8). CSV, appended per message; best-effort.
bool meshSdLog = false;
constexpr const char *MESH_LOG_PATH = "/meshtastic_log.csv";
// Raw RX diagnostic log (every frame, decoded or not) so an unattended overnight
// run can be inspected later. Best-effort; shares the same SD availability flag.
constexpr const char *MESH_RAW_PATH = "/meshtastic_raw.log";

// Append one line to the raw diagnostic log (best-effort; skips if no SD). All
// raw-log writes happen from the main loop (processMeshRx / decodeMeshFrame),
// never the RX ISR, so they don't race the radio on the shared SPI bus.
void logMeshRawLine(const String &s) {
    if (!meshSdLog) return;
    File f = SD.open(MESH_RAW_PATH, FILE_APPEND);
    if (!f) return;
    f.println(s);
    f.close();
}

// Current wall-clock as "HH:MM:SS" for message timestamps. Until the clock is set
// (the T-Deck syncs it from GPS/NTP), falls back to device uptime as "+HH:MM:SS" -
// the leading '+' marks it as relative (time since boot), not wall-clock.
String nowClock() {
    if (clock_set) {
        struct tm t = rtc.getTimeStruct();
        char b[9];
        snprintf(b, sizeof(b), "%02d:%02d:%02d", t.tm_hour, t.tm_min, t.tm_sec);
        return String(b);
    }
    uint32_t s = millis() / 1000;
    char b[16];
    snprintf(b, sizeof(b), "+%02u:%02u:%02u", (unsigned)(s / 3600), (unsigned)((s / 60) % 60),
             (unsigned)(s % 60));
    return String(b);
}

// Returns the known short name for a node, or "" if none heard yet.
String nodeName(uint32_t id) {
    for (auto &n : nodes)
        if (n.id == id) return n.name;
    return "";
}

// Append one message to the SD CSV log (best-effort; silently skips if no SD).
void logMeshMsg(const char *dir, uint32_t nodeId, const String &name, float rssi, float snr, const String &text) {
    if (!meshSdLog) return;
    File f = SD.open(MESH_LOG_PATH, FILE_APPEND);
    if (!f) return;
    String safe = text;
    safe.replace("\"", "'"); // keep the quoted CSV field intact
    char head[80];
    snprintf(head, sizeof(head), "%lu,%s,!%08x,", (unsigned long)millis(), dir, (unsigned)nodeId);
    f.print(head);
    f.print(name);
    char rf[24];
    snprintf(rf, sizeof(rf), ",%.0f,%.1f,\"", rssi, snr);
    f.print(rf);
    f.print(safe);
    f.println("\"");
    f.close();
}

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
    nodes.push_back({id, millis(), rssi, snr, 1, ""});
}

// Records/updates a heard node's short name from a NODEINFO User payload.
void setNodeName(uint32_t id, const String &name) {
    for (auto &n : nodes)
        if (n.id == id) {
            n.name = name;
            return;
        }
}

void addConvMsg(uint32_t from, bool mine, const String &text, float rssi, float snr) {
    ConvMsg m;
    m.from = from;
    m.mine = mine;
    m.text = text;
    m.rssi = rssi;
    m.snr = snr;
    m.atMs = millis();
    m.clk = nowClock();
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
        logMeshRawLine(String("  from=!") + String(hdr.from, HEX) + " undecodable (foreign key/non-Data) pt=" +
                       toHex(pt, ctLen));
        return;
    }
    Serial.printf("[Meshtastic]   decoded portnum=%u (%s) payloadLen=%u\n", (unsigned)dm.portnum,
                  portName(dm.portnum).c_str(), (unsigned)dm.payloadLen);
    // Decode summary + decrypted Data payload bytes (so screen output can be
    // correlated with exactly what was received/decrypted for this frame).
    {
        char meta[96];
        snprintf(meta, sizeof(meta), "  from=!%08x id=0x%08x port=%u ptlen=%u payloadhex=", (unsigned)hdr.from,
                 (unsigned)hdr.id, (unsigned)dm.portnum, (unsigned)dm.payloadLen);
        logMeshRawLine(String(meta) + toHex(dm.payload, dm.payloadLen));
    }

    // Any successfully-decoded frame proves a heard node on this channel.
    touchNode(hdr.from, rssi, snr);

    if (dm.portnum == meshtastic::TEXT_MESSAGE_APP) {
        // Guard: only surface/log genuinely displayable text. A binary payload
        // (mis-routed protobuf, wrong-key/collision garbage) is dropped here so it
        // never paints as symbols on screen nor lands in the SD log as garbage.
        String text;
        bool okText = meshtastic::sanitizeDisplayText(dm.payload, dm.payloadLen, text);
        if (!okText || text.length() == 0) {
            Serial.printf(
                "[Meshtastic]   TEXT payload not displayable (binary/non-text), not shown or logged\n"
            );
            logMeshRawLine(
                String("  TEXT DROPPED sanitize=") + (okText ? "ok-but-empty" : "rejected") +
                " len=" + String((unsigned)text.length())
            );
            return;
        }
        meshTextCount++;
        addConvMsg(hdr.from, false, text, rssi, snr);
        if (view == View::Conversation) needsRedraw = true;
        logMeshMsg("rx", hdr.from, nodeName(hdr.from), rssi, snr, text);
        // Record the exact string handed to the display so an on-screen anomaly
        // (e.g. a message rendering as ".") can be traced to its bytes.
        logMeshRawLine(String("  TEXT SHOWN len=") + String((unsigned)text.length()) + " display=\"" + text + "\"");
        Serial.printf(
            "[Meshtastic]   >>> TEXT from !%08x: \"%s\" (rssi=%.0fdBm snr=%.1fdB)\n", (unsigned)hdr.from,
            text.c_str(), rssi, snr
        );
    } else if (dm.portnum == meshtastic::NODEINFO_APP) {
        // Read-only: pull the node's short/long name to label the nodes list.
        char ln[32] = {0}, sn[12] = {0};
        if (meshtastic::decodeUserName(dm.payload, dm.payloadLen, ln, sizeof(ln), sn, sizeof(sn))) {
            String nm = strlen(sn) ? String(sn) : String(ln);
            setNodeName(hdr.from, nm);
            if (view == View::Nodes) needsRedraw = true;
            Serial.printf(
                "[Meshtastic]   node !%08x name: short=\"%s\" long=\"%s\"\n", (unsigned)hdr.from, sn, ln
            );
        }
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

// Core TX: encode Data(portnum,payload) -> AES-CTR encrypt with the LongFast key
// -> prepend header (to=broadcast, from=us, channel=0x08) -> duty-cycle guard ->
// half-duplex transmit -> re-arm RX. Shared by the text and self-NodeInfo paths.
// `reportBlock` = true makes a duty-cycle refusal update the on-screen "TX blocked"
// state (user messages); NodeInfo passes false so a background announce that gets
// deferred doesn't surface as a user-facing block. Returns true on a completed
// transmit; false if empty, encode-failed, blocked, or radio error. Runs only from
// the main loop (user action or the periodic announce) — never from the RX ISR.
bool txMeshData(uint32_t portnum, const uint8_t *payload, size_t payloadLen, bool reportBlock,
                const char *label) {
    if (!meshRadio) return false;

    uint8_t data[meshtastic::MAX_PLAINTEXT];
    size_t dataLen = meshtastic::encodeData(portnum, payload, payloadLen, data, sizeof(data));
    if (dataLen == 0) {
        Serial.printf("[Meshtastic] TX(%s): payload too long to encode\n", label);
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
        if (reportBlock) {
            lastTxBlocked = true;
            lastTxBlockedWaitS = (waitMs + 999) / 1000;
        }
        Serial.printf(
            "[Meshtastic] TX(%s) BLOCKED by duty cycle: pkt=%ums used=%ums/%ums budget, retry in ~%us\n",
            label, (unsigned)airMs, (unsigned)dutyCycle.usedMs(now), (unsigned)dutyCycle.budgetMs,
            (unsigned)((waitMs + 999) / 1000)
        );
        return false;
    }
    if (reportBlock) lastTxBlocked = false;

    // --- Transmit (half-duplex: mute RX IRQ, send, re-arm RX) ---
    txInProgress = true;
    meshIrqEnabled = false;
    int st = meshRadio->transmit(frame, frameLen);
    meshRadio->startReceive();
    meshIrqEnabled = true;
    txInProgress = false;

    if (st != RADIOLIB_ERR_NONE) {
        Serial.printf("[Meshtastic] TX(%s) failed: %d\n", label, st);
        return false;
    }

    dutyCycle.record(now, airMs);
    meshTxCount++;
    lastTxAtMs = now;
    Serial.printf(
        "[Meshtastic] TX #%lu (%s) id=0x%08x len=%u airtime=%ums used=%ums/%ums\n",
        (unsigned long)meshTxCount, label, (unsigned)id, (unsigned)frameLen, (unsigned)airMs,
        (unsigned)dutyCycle.usedMs(now), (unsigned)dutyCycle.budgetMs
    );
    return true;
}

// Compose a text message and transmit it. The ONLY user-facing TX path; runs only
// on explicit user action (compose/send or a serial trigger), never in a loop.
bool sendMeshText(const String &text) {
    if (text.length() == 0) return false;
    if (!txMeshData(meshtastic::TEXT_MESSAGE_APP, (const uint8_t *)text.c_str(), text.length(), true,
                    "text"))
        return false;
    // Show our own sent line in the conversation view and log it.
    addConvMsg(ourNodeId, true, text, 0, 0);
    needsRedraw = true;
    logMeshMsg("tx", ourNodeId, "", 0, 0, text);
    Serial.printf("[Meshtastic]   sent text: \"%s\"\n", text.c_str());
    return true;
}

// Broadcast our own NodeInfo (User: id/long_name/short_name) so peers list us by
// name rather than a bare !id. Duty-cycle guarded like any TX, but not surfaced as
// a user "TX blocked" if deferred. Not shown in the conversation or SD log.
void sendNodeInfo() {
    if (!meshRadio) return;
    char idStr[12];
    snprintf(idStr, sizeof(idStr), "!%08x", (unsigned)ourNodeId);
    uint8_t user[96];
    size_t userLen = meshtastic::encodeUser(idStr, meshLongName, meshShortName, user, sizeof(user));
    if (userLen == 0) return;
    if (txMeshData(meshtastic::NODEINFO_APP, user, userLen, false, "nodeinfo"))
        Serial.printf(
            "[Meshtastic]   NodeInfo announced: %s \"%s\" / \"%s\"\n", idStr, meshLongName, meshShortName
        );
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
        // Raw frame line for the diagnostic log (full ciphertext hex). Only frames
        // on our LongFast channel are logged, so the file isn't flooded with the
        // ambient other-channel traffic that we'd skip anyway.
        if (len >= meshtastic::HEADER_LEN && buf[13] == meshtastic::LONGFAST_CHANNEL_HASH) {
            char meta[112];
            snprintf(
                meta, sizeof(meta), "RX #%lu clk=%s t=%lums rssi=%.1f snr=%.1f crc=%s len=%u hex=",
                (unsigned long)meshRxCount, nowClock().c_str(), (unsigned long)millis(), rssi, snr,
                crcOk ? "OK" : "MISMATCH", (unsigned)len
            );
            logMeshRawLine(String(meta) + toHex(buf, len));
        }
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
                drawBodyRow(slot, y, m.clk + " >> " + shortText(m.text, 38), bruceConfig.priColor, TFT_BLACK);
            } else {
                String who = nodeName(m.from);
                if (who.length()) snprintf(meta, sizeof(meta), "%s: ", who.c_str());
                else snprintf(meta, sizeof(meta), "!%08x: ", (unsigned)m.from);
                char rf[24];
                snprintf(rf, sizeof(rf), "  %.0f/%.0f", m.rssi, m.snr);
                drawBodyRow(slot, y, m.clk + " " + shortText(String(meta) + m.text, 30) + rf, TFT_WHITE,
                            TFT_BLACK);
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
            char nameSeg[16] = {0};
            if (n.name.length()) snprintf(nameSeg, sizeof(nameSeg), " %s", n.name.c_str());
            snprintf(
                line, sizeof(line), "!%08x%s  %.0f/%.0f  x%lu  %lus", (unsigned)n.id, nameSeg, n.rssi,
                n.snr, (unsigned long)n.count, (unsigned long)ageS
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
    // Derive display names from the node-ID (short = last 4 hex, à la Meshtastic
    // defaults) so peers show a name without any extra config/storage.
    snprintf(meshShortName, sizeof(meshShortName), "%04x", (unsigned)(ourNodeId & 0xFFFF));
    snprintf(meshLongName, sizeof(meshLongName), "Bruce %s", meshShortName);
    Serial.printf(
        "[Meshtastic] our node-ID: !%08x name \"%s\"/\"%s\"\n", (unsigned)ourNodeId, meshLongName,
        meshShortName
    );

    // SD conversation logging (best-effort). Write a CSV header on first create.
    meshSdLog = false;
    if (sdcardMounted || setupSdCard()) {
        bool existed = SD.exists(MESH_LOG_PATH);
        File f = SD.open(MESH_LOG_PATH, FILE_APPEND);
        if (f) {
            if (!existed) f.println("uptime_ms,dir,nodeid,name,rssi,snr,text");
            f.close();
            meshSdLog = true;
            Serial.printf("[Meshtastic] SD log: %s\n", MESH_LOG_PATH);
        }
    }
    if (!meshSdLog) Serial.println("[Meshtastic] SD log disabled (no card)");
    else {
        // Session marker in the raw diagnostic log so overnight runs are delimited.
        char hdr[96];
        snprintf(hdr, sizeof(hdr), "=== session open t=%lums node=!%08x LongFast/EU868 869.525MHz ===",
                 (unsigned long)millis(), (unsigned)ourNodeId);
        logMeshRawLine(hdr);
        Serial.printf("[Meshtastic] raw RX log: %s\n", MESH_RAW_PATH);
    }

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
    nextNodeInfoAtMs = millis() + NODEINFO_FIRST_MS; // announce ourselves shortly after open

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

        // Periodic self-NodeInfo broadcast so peers list us by name. Signed millis
        // delta is wrap-safe; duty-cycle guarded inside sendNodeInfo(). Reschedule
        // regardless so a duty-deferred announce simply waits for the next window.
        if ((int32_t)(millis() - nextNodeInfoAtMs) >= 0) {
            sendNodeInfo();
            nextNodeInfoAtMs = millis() + NODEINFO_INTERVAL_MS;
            needsRedraw = true;
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
