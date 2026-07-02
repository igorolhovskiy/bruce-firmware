#if !defined(LITE_VERSION)
#include "LoRaRecon.h"
#include "LoRaWANParser.h"
#include "core/configPins.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "modules/lora/LoRaRF.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <globals.h>
#include <vector>

extern BruceConfigPins bruceConfigPins;

namespace {

// RECEIVE-ONLY: this file never calls a transmit API on the radio.
constexpr float RECON_BW_KHZ = 125.0f;
constexpr uint8_t RECON_CR = 5; // coding rate 4/5
constexpr uint8_t RECON_SYNC_WORD = 0x34; // LoRaWAN public sync word
constexpr size_t RECON_PREAMBLE = 8;
constexpr uint32_t HEARTBEAT_MS = 3000;
constexpr uint32_t REDRAW_MS = 250;
constexpr uint32_t SHORTCUT_POLL_MS = 80; // checkLetterShortcutPress() is not free; throttle it

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
constexpr size_t SWEEP_TABLE_ROWS = EU868_CHANNEL_COUNT * SF_DWELL_COUNT + 1; // +1 RX2 row

// SX1262 sensitivity floors, BW125/CR4:5 (§8) - for link-margin, never "distance".
float sensitivityFloorDbm(uint8_t sf) {
    switch (sf) {
    case 7: return -123.0f;
    case 8: return -126.0f;
    case 9: return -129.0f;
    case 10: return -132.0f;
    case 11: return -135.0f;
    default: return -137.0f; // SF12
    }
}
float linkMarginDb(float rssi, uint8_t sf) { return rssi - sensitivityFloorDbm(sf); }
String marginAssessment(float marginDb) {
    if (marginDb >= 40) return "very close / strong signal";
    if (marginDb >= 20) return "strong signal";
    if (marginDb >= 10) return "moderate signal";
    if (marginDb >= 5) return "weak - near edge of range";
    return "very weak - at the edge of range";
}

struct ComboStats {
    uint32_t packetCount = 0;
    float lastRssi = 0;
    uint32_t lastDevAddr = 0;
    bool hasLastDevAddr = false;
};

constexpr size_t MAX_CAPTURED_FRAMES = 40;
struct CapturedFrame {
    uint32_t seq = 0;
    uint32_t capturedAtMs = 0;
    float freqMHz = 0;
    uint8_t sf = 0;
    float bwKHz = RECON_BW_KHZ;
    float rssi = 0;
    float snr = 0;
    float airtimeMs = 0;
    size_t rawLen = 0;
    uint8_t raw[255];
    bool crcOk = true;
    bool isRx2 = false;
    LoRaWANFrame decoded;
};

SPIClass *reconSpi = nullptr;
Module *reconModule = nullptr;
SX1262 *reconRadio = nullptr;
volatile bool reconIrqEnabled = true;
volatile bool reconPacketReceived = false;
uint32_t reconPacketCount = 0;

enum class SweepStage { Channel, Rx2 };
SweepStage sweepStage = SweepStage::Channel;
size_t sweepChannelIdx = 0;
size_t sweepSfIdx = 0;
uint32_t stageStartMs = 0;
// Sf = brief's "recommended" variant (fix SF, hop channels). Exact = the
// brief's alternative (fix both channel+SF, no hopping at all). Rx2 = park
// on RX2 indefinitely.
enum class LockMode { None, Sf, Rx2, Exact };
LockMode lockMode = LockMode::None;
size_t lockedSfIdx = 0;      // meaningful while lockMode == Sf or Exact
size_t lockedChannelIdx = 0; // meaningful only while lockMode == Exact
ComboStats comboStats[EU868_CHANNEL_COUNT][SF_DWELL_COUNT];
uint32_t rx2PacketCount = 0;
std::vector<CapturedFrame> capturedFrames; // newest at back()

// Anomaly tracking: replayed DevNonce (per DevEUI) and FCnt regression (per
// DevAddr). In-session only, fixed-size ring-evicted tables (no heap growth
// over a long-running scan). Populated by processReconPacket() after each
// parseLoRaWANFrame() call - a single frame carries no history of its own.
constexpr size_t MAX_TRACKED_DEVADDRS = 32;
struct DevAddrTrack {
    uint32_t devAddr = 0;
    uint16_t lastFcnt = 0;
    bool valid = false;
};
DevAddrTrack devAddrTracker[MAX_TRACKED_DEVADDRS];
size_t devAddrTrackNext = 0; // ring cursor once the table is full

constexpr size_t MAX_TRACKED_DEVEUIS = 16;
constexpr size_t MAX_NONCES_PER_DEVEUI = 8;
struct DevEuiTrack {
    uint8_t devEUI[8] = {0};
    uint16_t nonces[MAX_NONCES_PER_DEVEUI] = {0};
    size_t nonceCount = 0;
    size_t nonceNext = 0; // ring cursor once nonces[] is full
    bool valid = false;
};
DevEuiTrack devEuiTracker[MAX_TRACKED_DEVEUIS];
size_t devEuiTrackNext = 0;

enum class ViewMode { Sweep, FrameList, FrameDetail };
ViewMode viewMode = ViewMode::Sweep;
int sweepCursor = 0; // 0..SWEEP_TABLE_ROWS-1 (last row = RX2)
int sweepScrollTop = 0;
int frameListCursor = 0; // 0 = newest
int frameListScrollTop = 0;
size_t detailFrameIdx = 0;
int detailScroll = 0;
bool needsRedraw = true;
bool viewNeedsFullClear = true; // set on every view transition; drawn once, not on every periodic refresh
bool exitFeatureRequested = false;

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
        (lockMode == LockMode::Sf || lockMode == LockMode::Exact) ? " [LOCKED]" : ""
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
    return SF_DWELL_TABLE[lockMode == LockMode::Sf ? lockedSfIdx : sweepSfIdx].dwellMs;
}

// Called only when the current dwell has elapsed; never called while
// lockMode == Rx2 (updateSweep() skips the whole time-based check then, so
// the radio stays genuinely parked on RX2 until the user unlocks it).
void advanceSweep() {
    if (sweepStage == SweepStage::Rx2) {
        enterChannel(0, lockMode == LockMode::Sf ? lockedSfIdx : 0);
        return;
    }
    if (lockMode == LockMode::Sf) {
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
    if (lockMode == LockMode::Rx2 || lockMode == LockMode::Exact) return; // parked indefinitely until unlocked
    if (millis() - stageStartMs >= currentDwellMs()) advanceSweep();
}

// Toggles the "hop channels at a fixed SF" lock mode, freezing at whatever
// SF is highlighted right now (Screen A "select to lock").
void toggleLockAt(size_t sfIdx) {
    if (lockMode == LockMode::Sf && lockedSfIdx == sfIdx) {
        lockMode = LockMode::None;
        Serial.println("[LoRaRecon] LOCK disabled: resuming full channel x SF sweep");
        return;
    }
    lockMode = LockMode::Sf;
    lockedSfIdx = sfIdx;
    Serial.printf("[LoRaRecon] LOCK enabled: SF%u fixed, hopping channels only\n", SF_DWELL_TABLE[sfIdx].sf);
}

// Toggles a genuine RX2 lock: parks the radio on RX2 indefinitely (no
// automatic return to the sweep) until the user selects the RX2 row again.
void toggleRx2Lock() {
    if (lockMode == LockMode::Rx2) {
        lockMode = LockMode::None;
        Serial.println("[LoRaRecon] RX2 lock disabled: resuming full channel x SF sweep");
        enterChannel(0, 0);
        return;
    }
    lockMode = LockMode::Rx2;
    enterRx2();
    Serial.println("[LoRaRecon] RX2 lock enabled: parked indefinitely on RX2 (869.525MHz SF12, inverted IQ)");
}

// Toggles the brief's alternative lock variant: fixes both channel AND SF,
// parked indefinitely on that one exact combo (no hopping at all), as
// opposed to toggleLockAt()'s "fix SF, still hop channels" recommended mode.
void toggleExactLock(size_t chIdx, size_t sfIdx) {
    if (lockMode == LockMode::Exact && lockedChannelIdx == chIdx && lockedSfIdx == sfIdx) {
        lockMode = LockMode::None;
        Serial.println("[LoRaRecon] EXACT LOCK disabled: resuming full channel x SF sweep");
        return;
    }
    lockMode = LockMode::Exact;
    lockedChannelIdx = chIdx;
    lockedSfIdx = sfIdx;
    enterChannel(chIdx, sfIdx);
    Serial.printf(
        "[LoRaRecon] EXACT LOCK enabled: parked on channel %u/%u SF%u (no hopping)\n", (unsigned)(chIdx + 1),
        (unsigned)EU868_CHANNEL_COUNT, SF_DWELL_TABLE[sfIdx].sf
    );
}

void resetStats() {
    for (size_t c = 0; c < EU868_CHANNEL_COUNT; c++) {
        for (size_t s = 0; s < SF_DWELL_COUNT; s++) comboStats[c][s] = ComboStats();
    }
    rx2PacketCount = 0;
    reconPacketCount = 0;
    capturedFrames.clear();
    for (auto &t : devAddrTracker) t = DevAddrTrack();
    for (auto &t : devEuiTracker) t = DevEuiTrack();
    devAddrTrackNext = 0;
    devEuiTrackNext = 0;
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

// Anomaly-tracking helper functions (state declared earlier, near comboStats).
bool devEuiEqual(const uint8_t a[8], const uint8_t b[8]) { return memcmp(a, b, 8) == 0; }

// Returns true if `fcnt` is lower than the last FCnt seen for this DevAddr
// (a regression - could mean a rejoin, a reset device, or a replay attempt).
bool trackFcntRegression(uint32_t devAddr, uint16_t fcnt) {
    for (size_t i = 0; i < MAX_TRACKED_DEVADDRS; i++) {
        if (devAddrTracker[i].valid && devAddrTracker[i].devAddr == devAddr) {
            bool regressed = fcnt < devAddrTracker[i].lastFcnt;
            devAddrTracker[i].lastFcnt = fcnt;
            return regressed;
        }
    }
    devAddrTracker[devAddrTrackNext] = {devAddr, fcnt, true};
    devAddrTrackNext = (devAddrTrackNext + 1) % MAX_TRACKED_DEVADDRS;
    return false;
}

// Returns true if this exact DevNonce was already seen from this DevEUI (a
// replayed join request).
bool trackDevNonceReplay(const uint8_t devEUI[8], uint16_t devNonce) {
    for (size_t i = 0; i < MAX_TRACKED_DEVEUIS; i++) {
        if (!devEuiTracker[i].valid || !devEuiEqual(devEuiTracker[i].devEUI, devEUI)) continue;
        DevEuiTrack &t = devEuiTracker[i];
        for (size_t n = 0; n < t.nonceCount; n++) {
            if (t.nonces[n] == devNonce) return true;
        }
        if (t.nonceCount < MAX_NONCES_PER_DEVEUI) {
            t.nonces[t.nonceCount++] = devNonce;
        } else {
            t.nonces[t.nonceNext] = devNonce;
            t.nonceNext = (t.nonceNext + 1) % MAX_NONCES_PER_DEVEUI;
        }
        return false;
    }
    DevEuiTrack &t = devEuiTracker[devEuiTrackNext];
    memcpy(t.devEUI, devEUI, 8);
    t.nonces[0] = devNonce;
    t.nonceCount = 1;
    t.nonceNext = 0;
    t.valid = true;
    devEuiTrackNext = (devEuiTrackNext + 1) % MAX_TRACKED_DEVEUIS;
    return false;
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
        if (decoded.isDataFrame) {
            decoded.anomalyFcntRegression = trackFcntRegression(decoded.devAddr, decoded.fcnt);
        } else if (decoded.isJoinRequest) {
            decoded.anomalyReplayedDevNonce = trackDevNonceReplay(decoded.devEUI, decoded.devNonce);
        }
        Serial.printf("[LoRaRecon] decoded: %s\n", decoded.mtypeName.c_str());
        for (const String &line : describeLoRaWANFrame(decoded)) {
            Serial.print("  - ");
            Serial.println(line);
        }

        if (sweepStage == SweepStage::Channel) {
            ComboStats &cs = comboStats[sweepChannelIdx][lockMode == LockMode::Sf ? lockedSfIdx : sweepSfIdx];
            cs.packetCount++;
            cs.lastRssi = rssi;
            if (decoded.isDataFrame) {
                cs.lastDevAddr = decoded.devAddr;
                cs.hasLastDevAddr = true;
            }
        } else {
            rx2PacketCount++;
        }

        CapturedFrame cf;
        cf.seq = reconPacketCount;
        cf.capturedAtMs = millis();
        cf.freqMHz = (sweepStage == SweepStage::Rx2) ? RX2_FREQ_MHZ : EU868_CHANNELS_MHZ[sweepChannelIdx];
        cf.sf = (sweepStage == SweepStage::Rx2) ? RX2_SF : SF_DWELL_TABLE[lockMode == LockMode::Sf ? lockedSfIdx : sweepSfIdx].sf;
        cf.rssi = rssi;
        cf.snr = snr;
        cf.airtimeMs = airtimeMs;
        cf.rawLen = len;
        memcpy(cf.raw, buf, len);
        cf.crcOk = crcOk;
        cf.isRx2 = (sweepStage == SweepStage::Rx2);
        cf.decoded = decoded;
        // decoded.frmPayloadPtr points into the transient `buf` above; relocate
        // it into cf.raw (a byte-identical, permanently-owned copy) so it stays
        // valid after this function returns. FRMPayload itself is never
        // decoded/displayed - only kept as opaque length+pointer, per spec.
        if (decoded.frmPayloadPtr) { cf.decoded.frmPayloadPtr = cf.raw + (decoded.frmPayloadPtr - buf); }
        capturedFrames.push_back(cf);
        if (capturedFrames.size() > MAX_CAPTURED_FRAMES) capturedFrames.erase(capturedFrames.begin());

        if (viewMode == ViewMode::Sweep) needsRedraw = true; // reflect new packet count promptly
    } else {
        Serial.printf("[LoRaRecon] RX read failed: %d\n", state);
    }

    reconRadio->startReceive();
    reconIrqEnabled = true;
}

// ---------------------------------------------------------------------------
// Screen A - sweep / activity table
// ---------------------------------------------------------------------------

void handleSweepInput() {
    if (check(PrevPress) || check(UpPress)) {
        if (sweepCursor > 0) sweepCursor--;
        needsRedraw = true;
    }
    if (check(NextPress) || check(DownPress)) {
        if (sweepCursor < (int)SWEEP_TABLE_ROWS - 1) sweepCursor++;
        needsRedraw = true;
    }
    if (check(SelPress)) {
        if (sweepCursor == (int)SWEEP_TABLE_ROWS - 1) {
            toggleRx2Lock();
        } else {
            size_t sfIdx = sweepCursor % SF_DWELL_COUNT;
            size_t chIdx = sweepCursor / SF_DWELL_COUNT;
            toggleLockAt(sfIdx);
            if (lockMode == LockMode::Sf) enterChannel(chIdx, sfIdx); // jump immediately to the selected combo
        }
        needsRedraw = true;
    }
    if (check(EscPress)) {
        exitFeatureRequested = true;
        return;
    }

    static uint32_t lastShortcutCheck = 0;
    if (millis() - lastShortcutCheck > SHORTCUT_POLL_MS) {
        lastShortcutCheck = millis();
        char c = checkLetterShortcutPress();
        if (c == 'f' || c == 'F') {
            viewMode = ViewMode::FrameList;
            frameListCursor = 0;
            frameListScrollTop = 0;
            viewNeedsFullClear = true;
            needsRedraw = true;
        } else if (c == 'r' || c == 'R') {
            resetStats();
            needsRedraw = true;
        } else if (c == 'x' || c == 'X') {
            if (sweepCursor != (int)SWEEP_TABLE_ROWS - 1) { // RX2 row has its own dedicated lock via Select
                size_t sfIdx = sweepCursor % SF_DWELL_COUNT;
                size_t chIdx = sweepCursor / SF_DWELL_COUNT;
                toggleExactLock(chIdx, sfIdx);
                needsRedraw = true;
            }
        }
    }
}

// Cache of what's currently drawn in each visible screen-row slot, so a
// periodic refresh only touches rows whose content actually changed instead
// of blindly re-filling+re-drawing all ~18 rows every cycle (that redundant
// redraw was the remaining source of visible flicker).
constexpr size_t MAX_VISIBLE_SWEEP_ROWS = 24;
String sweepRowCache[MAX_VISIBLE_SWEEP_ROWS];
String sweepLockLineCache;

void drawSweepScreen() {
    constexpr int rowH = 11;
    constexpr int listTop = 30;
    const int listBottom = tftHeight - 14;
    const int visibleRows = (listBottom - listTop) / rowH;

    // Static chrome (title/footer/divider) is drawn once per view-entry, not
    // on every periodic refresh - repeatedly fillScreen()-ing on a timer was
    // causing a visible flash even with no new data.
    if (viewNeedsFullClear) {
        viewNeedsFullClear = false;
        tft.fillScreen(TFT_BLACK);
        tft.setTextSize(FM);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawCentreString("LoRa Recon - Sweep", tftWidth / 2, 4, 1);
        tft.setTextSize(FP);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.drawFastHLine(0, tftHeight - 13, tftWidth, TFT_DARKGREY);
        tft.drawString("Up/Dn nav Sel/x=lock f=frames r=reset Bksp=exit", 2, tftHeight - 11, 1);
        for (auto &c : sweepRowCache) c = "\x01"; // force every row slot to redraw this pass
        sweepLockLineCache = "\x01"; // force lock-status line to redraw this pass
    }
    tft.setTextSize(FP);

    // Dedicated, always-visible lock-status line - lock state was previously
    // only shown via small per-row 'L' markers, which read as "sweeping got
    // stuck" rather than "lock is intentionally on". Redrawn whenever the
    // lock state text changes (not just on full clear), independent of the
    // row-list redraw below.
    String lockLine;
    if (lockMode == LockMode::Sf) {
        lockLine = "LOCK: SF" + String(SF_DWELL_TABLE[lockedSfIdx].sf) + " (hopping channels only)";
    } else if (lockMode == LockMode::Exact) {
        lockLine = "LOCK: CH" + String((unsigned)(lockedChannelIdx + 1)) + "/" + String((unsigned)EU868_CHANNEL_COUNT) +
                   " SF" + String(SF_DWELL_TABLE[lockedSfIdx].sf) + " (exact, no hopping)";
    } else if (lockMode == LockMode::Rx2) {
        lockLine = "LOCK: RX2 (parked - not sweeping)";
    } else {
        lockLine = "LOCK: off (sweeping all channels x SF)";
    }
    if (lockLine != sweepLockLineCache) {
        sweepLockLineCache = lockLine;
        tft.fillRect(0, 17, tftWidth, rowH, TFT_BLACK);
        tft.setTextColor(lockMode != LockMode::None ? TFT_YELLOW : TFT_DARKGREY, TFT_BLACK);
        tft.drawString(lockLine, 2, 17, 1);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
    }

    if (sweepCursor < sweepScrollTop) sweepScrollTop = sweepCursor;
    if (sweepCursor >= sweepScrollTop + visibleRows) sweepScrollTop = sweepCursor - visibleRows + 1;
    if (sweepScrollTop < 0) sweepScrollTop = 0;

    for (int row = 0; row < visibleRows; row++) {
        int idx = sweepScrollTop + row;
        int y = listTop + row * rowH;
        if (idx >= (int)SWEEP_TABLE_ROWS) {
            tft.fillRect(0, y, tftWidth, rowH, TFT_BLACK);
            continue;
        }
        bool isCursor = (idx == sweepCursor);
        bool isRx2Row = (idx == (int)SWEEP_TABLE_ROWS - 1);
        bool isActive;
        char line[48];

        if (isRx2Row) {
            isActive = (sweepStage == SweepStage::Rx2);
            snprintf(
                line, sizeof(line), "%c%cRX2  %.3f SF%-2u n=%-4lu", isActive ? '>' : ' ',
                lockMode == LockMode::Rx2 ? 'L' : ' ', RX2_FREQ_MHZ, RX2_SF, (unsigned long)rx2PacketCount
            );
        } else {
            size_t chIdx = idx / SF_DWELL_COUNT;
            size_t sfIdx = idx % SF_DWELL_COUNT;
            const ComboStats &cs = comboStats[chIdx][sfIdx];
            isActive = (sweepStage == SweepStage::Channel && chIdx == sweepChannelIdx &&
                        sfIdx == (lockMode == LockMode::Sf ? lockedSfIdx : sweepSfIdx));
            bool isLockedSf = lockMode == LockMode::Sf && sfIdx == lockedSfIdx;
            bool isExactLocked = lockMode == LockMode::Exact && chIdx == lockedChannelIdx && sfIdx == lockedSfIdx;
            char marker = isExactLocked ? 'X' : (isLockedSf ? 'L' : ' ');
            char rssiBuf[6];
            if (cs.packetCount) snprintf(rssiBuf, sizeof(rssiBuf), "%-4.0f", cs.lastRssi);
            else snprintf(rssiBuf, sizeof(rssiBuf), "  --");
            char addrBuf[10];
            if (cs.hasLastDevAddr) snprintf(addrBuf, sizeof(addrBuf), "%08lX", (unsigned long)cs.lastDevAddr);
            else snprintf(addrBuf, sizeof(addrBuf), "--------");
            snprintf(
                line, sizeof(line), "%c%c%.3f SF%-2u n=%-4lu %s %s", isActive ? '>' : ' ', marker,
                EU868_CHANNELS_MHZ[chIdx], SF_DWELL_TABLE[sfIdx].sf, (unsigned long)cs.packetCount, rssiBuf, addrBuf
            );
        }

        String key = String(isCursor ? 'C' : '.') + line;
        if (row < (int)MAX_VISIBLE_SWEEP_ROWS && sweepRowCache[row] == key) continue; // unchanged, skip redraw
        if (row < (int)MAX_VISIBLE_SWEEP_ROWS) sweepRowCache[row] = key;

        uint16_t bg = isCursor ? bruceConfig.priColor : TFT_BLACK;
        tft.fillRect(0, y, tftWidth, rowH, bg);
        tft.setTextColor(isCursor ? bruceConfig.bgColor : (isActive ? TFT_GREEN : TFT_WHITE), bg);
        tft.drawString(line, 2, y, 1);
    }
}

// ---------------------------------------------------------------------------
// Screen B - captured frames list
// ---------------------------------------------------------------------------

const char *mtypeShortCode(LoRaWANMType mtype) {
    switch (mtype) {
    case LoRaWANMType::JoinRequest: return "JReq";
    case LoRaWANMType::JoinAccept: return "JAcc";
    case LoRaWANMType::UnconfirmedDataUp: return "UpU ";
    case LoRaWANMType::UnconfirmedDataDown: return "DnU ";
    case LoRaWANMType::ConfirmedDataUp: return "UpC ";
    case LoRaWANMType::ConfirmedDataDown: return "DnC ";
    case LoRaWANMType::RejoinRequest: return "Rejn";
    default: return "Prop";
    }
}

void handleFrameListInput() {
    if (check(EscPress)) {
        viewMode = ViewMode::Sweep;
        viewNeedsFullClear = true;
        needsRedraw = true;
        return;
    }
    if (capturedFrames.empty()) return;

    if (check(PrevPress) || check(UpPress)) {
        if (frameListCursor > 0) frameListCursor--;
        needsRedraw = true;
    }
    if (check(NextPress) || check(DownPress)) {
        if (frameListCursor < (int)capturedFrames.size() - 1) frameListCursor++;
        needsRedraw = true;
    }
    if (check(SelPress)) {
        detailFrameIdx = capturedFrames.size() - 1 - frameListCursor; // newest-first cursor -> storage index
        detailScroll = 0;
        viewMode = ViewMode::FrameDetail;
        viewNeedsFullClear = true;
        needsRedraw = true;
    }
}

void drawFrameListScreen() {
    constexpr int rowH = 11;
    constexpr int listTop = 22;
    const int listBottom = tftHeight - 14;
    const int visibleRows = (listBottom - listTop) / rowH;

    if (viewNeedsFullClear) {
        viewNeedsFullClear = false;
        tft.fillScreen(TFT_BLACK);
        tft.setTextSize(FM);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawCentreString("LoRa Recon - Frames", tftWidth / 2, 4, 1);
        tft.setTextSize(FP);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.drawFastHLine(0, tftHeight - 13, tftWidth, TFT_DARKGREY);
        tft.drawString(capturedFrames.empty() ? "Bksp=back" : "Up/Dn nav Sel=detail Bksp=back", 2, tftHeight - 11, 1);
    }
    tft.setTextSize(FP);

    if (capturedFrames.empty()) {
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.drawCentreString("No frames captured yet", tftWidth / 2, tftHeight / 2, 1);
        return;
    }

    const int total = (int)capturedFrames.size();

    if (frameListCursor < frameListScrollTop) frameListScrollTop = frameListCursor;
    if (frameListCursor >= frameListScrollTop + visibleRows) frameListScrollTop = frameListCursor - visibleRows + 1;
    if (frameListScrollTop < 0) frameListScrollTop = 0;

    for (int row = 0; row < visibleRows; row++) {
        int cursorIdx = frameListScrollTop + row; // 0 = newest
        int y = listTop + row * rowH;
        if (cursorIdx >= total) {
            tft.fillRect(0, y, tftWidth, rowH, TFT_BLACK);
            continue;
        }
        size_t storeIdx = total - 1 - cursorIdx;
        const CapturedFrame &f = capturedFrames[storeIdx];
        bool isCursor = (cursorIdx == frameListCursor);
        bool anomaly = f.decoded.anomalyReplayedDevNonce || f.decoded.anomalyFcntRegression;

        char idStr[10];
        if (f.decoded.isJoinRequest) {
            snprintf(
                idStr, sizeof(idStr), "%02X%02X%02X%02X", f.decoded.devEUI[0], f.decoded.devEUI[1],
                f.decoded.devEUI[2], f.decoded.devEUI[3]
            );
        } else if (f.decoded.isDataFrame) {
            snprintf(idStr, sizeof(idStr), "%08lX", (unsigned long)f.decoded.devAddr);
        } else {
            snprintf(idStr, sizeof(idStr), "--------");
        }

        uint32_t ageS = (millis() - f.capturedAtMs) / 1000;
        char line[48];
        snprintf(
            line, sizeof(line), "%c%5lus %s %s %-4.0fdBm", anomaly ? '!' : ' ', (unsigned long)ageS,
            mtypeShortCode(f.decoded.mtype), idStr, f.rssi
        );

        uint16_t bg = isCursor ? bruceConfig.priColor : TFT_BLACK;
        tft.fillRect(0, y, tftWidth, rowH, bg);
        tft.setTextColor(isCursor ? bruceConfig.bgColor : (anomaly ? TFT_RED : TFT_WHITE), bg);
        tft.drawString(line, 2, y, 1);
    }
}

// ---------------------------------------------------------------------------
// Screen C - frame detail (human-readable)
// ---------------------------------------------------------------------------

std::vector<String> wrapLine(const String &text, size_t maxChars) {
    std::vector<String> out;
    if (text.length() == 0) {
        out.push_back("");
        return out;
    }
    int start = 0;
    int len = text.length();
    while (start < len) {
        int remaining = len - start;
        if (remaining <= (int)maxChars) {
            out.push_back(text.substring(start));
            break;
        }
        int breakAt = start + maxChars;
        int lastSpace = text.lastIndexOf(' ', breakAt);
        if (lastSpace <= start) lastSpace = breakAt; // no space to break on - hard break
        out.push_back(text.substring(start, lastSpace));
        start = lastSpace + 1;
    }
    return out;
}

std::vector<String> buildDetailLines(const CapturedFrame &f) {
    std::vector<String> logical;
    logical.push_back("-- RF --");
    char buf[64];
    snprintf(buf, sizeof(buf), "Freq %.3f MHz  SF%u  BW%.0fkHz", f.freqMHz, f.sf, f.bwKHz);
    logical.push_back(buf);
    snprintf(buf, sizeof(buf), "RSSI %.1f dBm   SNR %.1f dB", f.rssi, f.snr);
    logical.push_back(buf);
    float margin = linkMarginDb(f.rssi, f.sf);
    logical.push_back(
        "Link margin " + String(margin, 1) + " dB - " + marginAssessment(margin) + " (not distance - depends on "
                                                                                     "the sender's TX power/antenna)"
    );
    snprintf(buf, sizeof(buf), "Length %u bytes   Airtime %.2f ms", (unsigned)f.rawLen, f.airtimeMs);
    logical.push_back(buf);
    if (!f.crcOk) logical.push_back("PHY CRC: MISMATCH - frame may be corrupted");
    if (f.isRx2) logical.push_back("Captured on RX2 (downlink) - inverted IQ");
    logical.push_back("");
    logical.push_back("-- Protocol --");
    for (const String &l : describeLoRaWANFrame(f.decoded)) logical.push_back(l);

    std::vector<String> wrapped;
    for (auto &l : logical) {
        for (auto &w : wrapLine(l, 50)) wrapped.push_back(w);
    }
    return wrapped;
}

void handleFrameDetailInput() {
    if (check(EscPress)) {
        viewMode = ViewMode::FrameList;
        viewNeedsFullClear = true;
        needsRedraw = true;
        return;
    }
    if (check(PrevPress) || check(UpPress)) {
        if (detailScroll > 0) detailScroll--;
        needsRedraw = true;
    }
    if (check(NextPress) || check(DownPress)) {
        detailScroll++; // clamped in drawFrameDetailScreen()
        needsRedraw = true;
    }
}

void drawFrameDetailScreen() {
    constexpr int rowH = 11;
    constexpr int top = 22;
    const int bottom = tftHeight - 14;
    const int visibleRows = (bottom - top) / rowH;

    if (viewNeedsFullClear) {
        viewNeedsFullClear = false;
        tft.fillScreen(TFT_BLACK);
        tft.setTextSize(FM);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawCentreString("LoRa Recon - Detail", tftWidth / 2, 4, 1);
        tft.setTextSize(FP);
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        tft.drawFastHLine(0, tftHeight - 13, tftWidth, TFT_DARKGREY);
        tft.drawString(
            detailFrameIdx >= capturedFrames.size() ? "Bksp=back" : "Up/Dn scroll  Bksp=back", 2, tftHeight - 11, 1
        );
    }
    tft.setTextSize(FP);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);

    if (detailFrameIdx >= capturedFrames.size()) {
        tft.drawCentreString("Frame no longer available", tftWidth / 2, tftHeight / 2, 1);
        return;
    }

    std::vector<String> lines = buildDetailLines(capturedFrames[detailFrameIdx]);

    int maxScroll = (int)lines.size() - visibleRows;
    if (maxScroll < 0) maxScroll = 0;
    if (detailScroll > maxScroll) detailScroll = maxScroll;
    if (detailScroll < 0) detailScroll = 0;

    for (int row = 0; row < visibleRows; row++) {
        int idx = detailScroll + row;
        int y = top + row * rowH;
        tft.fillRect(0, y, tftWidth, rowH, TFT_BLACK);
        if (idx >= (int)lines.size()) continue;
        tft.drawString(lines[idx], 2, y, 1);
    }
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
    delay(600); // brief, so the self-test result is actually readable before the sweep view takes over

    resetStats();
    lockMode = LockMode::None;
    lockedChannelIdx = 0;
    viewMode = ViewMode::Sweep;
    sweepCursor = 0;
    sweepScrollTop = 0;
    frameListCursor = 0;
    frameListScrollTop = 0;
    needsRedraw = true;
    viewNeedsFullClear = true;
    exitFeatureRequested = false;

    if (!startReconRadio()) {
        while (true) {
            if (check(EscPress)) return;
            delay(20);
        }
    }
    enterChannel(0, 0);

    uint32_t lastHeartbeat = millis();
    uint32_t lastSweepRedraw = 0;
    while (!exitFeatureRequested) {
        processReconPacket();
        updateSweep();

        if (millis() - lastHeartbeat > HEARTBEAT_MS) {
            lastHeartbeat = millis();
            Serial.printf(
                "[LoRaRecon] listening... packets=%lu uptime=%lus\n", (unsigned long)reconPacketCount,
                (unsigned long)(millis() / 1000)
            );
        }

        switch (viewMode) {
        case ViewMode::Sweep:
            handleSweepInput();
            if (millis() - lastSweepRedraw > REDRAW_MS) {
                lastSweepRedraw = millis();
                needsRedraw = true;
            }
            break;
        case ViewMode::FrameList: handleFrameListInput(); break;
        case ViewMode::FrameDetail: handleFrameDetailInput(); break;
        }

        if (needsRedraw) {
            switch (viewMode) {
            case ViewMode::Sweep: drawSweepScreen(); break;
            case ViewMode::FrameList: drawFrameListScreen(); break;
            case ViewMode::FrameDetail: drawFrameDetailScreen(); break;
            }
            needsRedraw = false;
        }

        delay(5);
    }

    stopReconRadio();
    Serial.println("[LoRaRecon] stopped, exiting");
}
#endif
