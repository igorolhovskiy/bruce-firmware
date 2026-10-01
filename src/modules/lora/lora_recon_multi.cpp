#include "lora_recon_multi.h"
#if !defined(LITE_VERSION)

#include "LoRaRF.h"
#include "MeshtasticCodec.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "lora_classify.h"
#include "lora_nodes.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <algorithm>
#include <globals.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 of the multi-protocol LoRa recon (bruce-lora-multiproto-TASK.md):
// passive Meshtastic node discovery. Radio bring-up mirrors Meshtastic.cpp's
// LongFast/EU868 config but RX-only (no setOutputPower / no transmit path). Each
// frame -> loramp::classify() -> NodeTable + a recent-frames ring. Two tabs
// (NODES / FRAMES), per-row diffed, serial-mirrored. ESC exits and tears the
// radio down.
// ─────────────────────────────────────────────────────────────────────────────

namespace {

using namespace loramp;

// LongFast / EU_868 (same constants as Meshtastic.cpp).
constexpr float MESH_FREQ_MHZ = 869.525f;
constexpr float MESH_BW_KHZ = 250.0f;
constexpr uint8_t MESH_SF = 11;
constexpr uint8_t MESH_CR = 5;
constexpr uint8_t MESH_SYNC_WORD = 0x2b;
constexpr size_t MESH_PREAMBLE = 16;

SPIClass *rmSpi = nullptr;
Module *rmModule = nullptr;
SX1262 *rmRadio = nullptr;
volatile bool rmPacketReceived = false;

void IRAM_ATTR onRmPacket() { rmPacketReceived = true; }

void clearRadio() {
    if (rmRadio) {
        delete rmRadio;
        rmRadio = nullptr;
    }
    if (rmModule) {
        delete rmModule;
        rmModule = nullptr;
    }
}

bool radioUp() {
    const int irqPin = getLoraIrqPin();
    if (irqPin == GPIO_NUM_NC) {
        Serial.println("[LoRaMP] LoRa IRQ pin not configured!");
        return false;
    }
    const int busyPin = getLoraBusyPin();
    rmSpi = selectLoraSPIBus();
    clearRadio();
    rmModule = new Module(getLoraCsPin(), irqPin, getLoraResetPin(), busyPin, *rmSpi);
    rmRadio = new SX1262(rmModule);

    int st = rmRadio->begin(MESH_FREQ_MHZ);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->setBandwidth(MESH_BW_KHZ);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->setSpreadingFactor(MESH_SF);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->setCodingRate(MESH_CR);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->setPreambleLength(MESH_PREAMBLE);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->setSyncWord(MESH_SYNC_WORD);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->setCRC(1);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->invertIQ(false);
    if (st == RADIOLIB_ERR_NONE) rmRadio->setDio1Action(onRmPacket);
    if (st == RADIOLIB_ERR_NONE) st = rmRadio->startReceive();
    if (st != RADIOLIB_ERR_NONE) {
        Serial.printf("[LoRaMP] radio init failed err=%d\n", st);
        clearRadio();
        return false;
    }
    Serial.printf("[LoRaMP] radio up: %.3fMHz SF%u BW%.0f sync=0x%02X (RX-only)\n", MESH_FREQ_MHZ,
                  MESH_SF, MESH_BW_KHZ, MESH_SYNC_WORD);
    return true;
}

// ── State ────────────────────────────────────────────────────────────────────
NodeTable nodeTable;
uint8_t meshKey[16];
size_t meshKeyLen = 0;

struct FrameRow {
    char text[40];
    int8_t rssi;
    uint8_t proto;
};
constexpr size_t FRAMES_MAX = 40;
std::vector<FrameRow> frames; // newest at back
uint32_t rxCount = 0, unknownCount = 0;

enum class Tab { Nodes, Frames };
Tab tab = Tab::Nodes;
int cursor = 0, scroll = 0;

// ── RX drain ──────────────────────────────────────────────────────────────────
void drainPacket() {
    if (!rmPacketReceived || !rmRadio) return;
    rmPacketReceived = false;

    size_t len = rmRadio->getPacketLength();
    if (len == 0 || len > 255) {
        rmRadio->startReceive();
        return;
    }
    uint8_t buf[255];
    int st = rmRadio->readData(buf, len);
    bool crcOk = (st == RADIOLIB_ERR_NONE);
    if (crcOk || st == RADIOLIB_ERR_CRC_MISMATCH) {
        int8_t rssi = (int8_t)rmRadio->getRSSI();
        float snr = rmRadio->getSNR();
        rxCount++;

        RadioCtx ctx = {MESH_FREQ_MHZ, MESH_SF, MESH_SYNC_WORD};
        Classified c;
        classify(buf, len, ctx, meshKey, meshKeyLen, rssi, snr, c);
        if (c.proto == LP_UNKNOWN) unknownCount++;
        else nodeTable.update(c, millis());

        FrameRow fr = {};
        summary(c, fr.text, sizeof(fr.text));
        fr.rssi = rssi;
        fr.proto = c.proto;
        if (frames.size() >= FRAMES_MAX) frames.erase(frames.begin());
        frames.push_back(fr);
        Serial.printf("[LoRaMP] RX #%lu len=%u rssi=%d snr=%.1f -> %s\n", (unsigned long)rxCount,
                      (unsigned)len, rssi, snr, fr.text);
    }
    rmRadio->startReceive();
}

// ── Rendering (per-row diffed) ───────────────────────────────────────────────
constexpr int CHROME_H = 26;
constexpr int FOOTER_H = 12;
constexpr int ROW_H = 11;
constexpr int MAX_ROWS = 18;
String rowCache[MAX_ROWS];
uint16_t rowFgCache[MAX_ROWS];
String chromeCache[2];
String footerCache;
bool fullClear = true;

void resetCache() {
    for (int i = 0; i < MAX_ROWS; i++) {
        rowCache[i] = "\x01";
        rowFgCache[i] = 0xDEAD;
    }
    chromeCache[0] = chromeCache[1] = "\x01";
    footerCache = "\x01";
}
void drawRow(int slot, int y, const String &text, uint16_t fg) {
    if (slot < 0 || slot >= MAX_ROWS) return;
    if (rowCache[slot] == text && rowFgCache[slot] == fg) return;
    rowCache[slot] = text;
    rowFgCache[slot] = fg;
    tft.fillRect(0, y - 1, tftWidth, ROW_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(fg, TFT_BLACK);
    tft.drawString(text, 4, y);
}
void drawChrome() {
    tft.setTextSize(FP);
    char l0[64];
    snprintf(l0, sizeof(l0), "LoRa Multi  LongFast 869.5");
    if (chromeCache[0] != l0) {
        chromeCache[0] = l0;
        tft.fillRect(0, 0, tftWidth, 11, TFT_BLACK);
        tft.setTextColor(bruceConfig.priColor, TFT_BLACK);
        tft.drawString(l0, 4, 2);
    }
    char l1[64];
    snprintf(l1, sizeof(l1), "%s  nodes:%u rx:%lu ?:%lu", tab == Tab::Nodes ? "[NODES]" : "[FRAMES]",
             (unsigned)nodeTable.size(), (unsigned long)rxCount, (unsigned long)unknownCount);
    if (chromeCache[1] != l1) {
        chromeCache[1] = l1;
        tft.fillRect(0, 13, tftWidth, 12, TFT_BLACK);
        tft.setTextColor(nodeTable.size() ? TFT_GREEN : TFT_YELLOW, TFT_BLACK);
        tft.drawString(l1, 4, 14);
        tft.drawFastHLine(0, CHROME_H - 2, tftWidth, TFT_DARKGREY);
    }
}
void drawFooter() {
    String hint = "SEL tab  ^v scroll  <-exit";
    if (footerCache == hint) return;
    footerCache = hint;
    tft.fillRect(0, tftHeight - FOOTER_H, tftWidth, FOOTER_H, TFT_BLACK);
    tft.setTextSize(FP);
    tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
    tft.drawString(hint, 4, tftHeight - FOOTER_H + 1);
}
void flagStr(uint8_t f, char *out, size_t cap) {
    snprintf(out, cap, "%s%s%s%s", (f & NF_HOPS_HIGH) ? "H" : "", (f & NF_MQTT) ? "M" : "",
             (f & NF_OLD_FW) ? "O" : "", (f & NF_CHATTY) ? "C" : "");
}
void drawNodes(int rows) {
    int total = (int)nodeTable.size();
    if (cursor >= total) cursor = total ? total - 1 : 0;
    if (cursor < 0) cursor = 0;
    if (cursor < scroll) scroll = cursor;
    if (cursor >= scroll + rows) scroll = cursor - rows + 1;
    if (scroll > total - rows) scroll = total > rows ? total - rows : 0;
    if (scroll < 0) scroll = 0;

    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int li = scroll + slot;
        if (li >= total) {
            if (total == 0 && slot == 0) drawRow(slot, y, "  (listening for Meshtastic...)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const LoraNode &n = nodeTable.at(li);
        char fl[6];
        flagStr(n.flags, fl, sizeof(fl));
        String label = n.name[0] ? String(n.name) : (String("!") + String(n.id, HEX));
        if (label.length() > 14) label = label.substring(0, 14);
        char line[48];
        snprintf(line, sizeof(line), "%c%s %d x%u %s", li == cursor ? '>' : ' ', label.c_str(),
                 n.rssi, n.count, fl);
        uint16_t fg = li == cursor ? TFT_CYAN : (n.flags & (NF_HOPS_HIGH | NF_MQTT)) ? TFT_YELLOW : TFT_WHITE;
        drawRow(slot, y, line, fg);
    }
}
void drawFrames(int rows) {
    int total = (int)frames.size();
    for (int slot = 0; slot < rows; slot++) {
        int y = CHROME_H + slot * ROW_H;
        int li = total - 1 - slot; // newest first
        if (li < 0) {
            if (total == 0 && slot == 0) drawRow(slot, y, "  (no frames yet)", TFT_DARKGREY);
            else drawRow(slot, y, "", TFT_WHITE);
            continue;
        }
        const FrameRow &fr = frames[li];
        char line[52];
        snprintf(line, sizeof(line), " %s %d", fr.text, fr.rssi);
        uint16_t fg = fr.proto == LP_MESHTASTIC ? TFT_WHITE : TFT_DARKGREY;
        drawRow(slot, y, line, fg);
    }
}
void rmDraw() {
    if (fullClear) {
        tft.fillScreen(TFT_BLACK);
        resetCache();
        fullClear = false;
    }
    drawChrome();
    int rows = (tftHeight - CHROME_H - FOOTER_H) / ROW_H;
    if (rows > MAX_ROWS) rows = MAX_ROWS;
    if (tab == Tab::Nodes) drawNodes(rows);
    else drawFrames(rows);
    drawFooter();
}

} // namespace

void loraReconMulti() {
    Serial.println("[LoRaMP] multi-proto LoRa recon starting (Phase 1: Meshtastic, RX-only)");
    bool stOk = loramp::runLoraMultiSelfTest();
    Serial.printf("[LoRaMP] self-test %s\n", stOk ? "PASS" : "FAIL");

    nodeTable.clear();
    frames.clear();
    rxCount = unknownCount = 0;
    tab = Tab::Nodes;
    cursor = scroll = 0;
    fullClear = true;
    rmPacketReceived = false;
    meshtastic::expandPsk(1, meshKey, meshKeyLen); // LongFast default key

    if (!radioUp()) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.drawCentreString("LoRa radio init failed", tftWidth / 2, tftHeight / 2, 1);
        delay(1500);
        return;
    }

    rmDraw();
    while (true) {
        if (check(EscPress)) break;
        drainPacket();

        if (check(SelPress)) {
            tab = (tab == Tab::Nodes) ? Tab::Frames : Tab::Nodes;
            cursor = scroll = 0;
            fullClear = true;
        }
        if (check(PrevPress) && tab == Tab::Nodes && cursor > 0) cursor--;
        if (check(NextPress) && tab == Tab::Nodes) cursor++;

        rmDraw();
        delay(15);
    }

    if (rmRadio) rmRadio->standby();
    clearRadio();
    Serial.printf("[LoRaMP] stopped. nodes=%u rx=%lu unknown=%lu\n", (unsigned)nodeTable.size(),
                  (unsigned long)rxCount, (unsigned long)unknownCount);
}

#endif
