#if !defined(LITE_VERSION)
#include "LoRaWANParser.h"
#include <Arduino.h>

namespace {

String hexByte(uint8_t b) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02X", b);
    return String(buf);
}

String hexBytes(const uint8_t *data, size_t len) {
    String s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) s += hexByte(data[i]);
    return s;
}

// FOpts MAC command metadata, keyed by CID. Uplink rows are the device's
// "Ans" replies (or "Req" for device-initiated ones like LinkCheckReq /
// DeviceTimeReq); downlink rows are the network's "Req"/"Ans" commands.
// Lengths are the LoRaWAN 1.0.x fixed payload sizes for that CID+direction.
struct MacCidInfo {
    uint8_t cid;
    const char *upName;
    int upLen; // -1 = variable/unsupported here
    const char *dnName;
    int dnLen;
};

const MacCidInfo MAC_CID_TABLE[] = {
    {0x02, "LinkCheckReq",     0, "LinkCheckAns",     2},
    {0x03, "LinkADRAns",       1, "LinkADRReq",       4},
    {0x04, "DutyCycleAns",     0, "DutyCycleReq",     1},
    {0x05, "RXParamSetupAns",  1, "RXParamSetupReq",  4},
    {0x06, "DevStatusAns",     2, "DevStatusReq",     0},
    {0x07, "NewChannelAns",    1, "NewChannelReq",    5},
    {0x08, "RXTimingSetupAns", 0, "RXTimingSetupReq", 1},
    {0x09, "TxParamSetupAns",  0, "TxParamSetupReq",  1},
    {0x0A, "DlChannelAns",     1, "DlChannelReq",     4},
    {0x0D, "DeviceTimeReq",    0, "DeviceTimeAns",    5},
};
constexpr size_t MAC_CID_TABLE_LEN = sizeof(MAC_CID_TABLE) / sizeof(MAC_CID_TABLE[0]);

const MacCidInfo *findCidInfo(uint8_t cid) {
    for (size_t i = 0; i < MAC_CID_TABLE_LEN; i++) {
        if (MAC_CID_TABLE[i].cid == cid) return &MAC_CID_TABLE[i];
    }
    return nullptr;
}

String describeMacCommandPayload(uint8_t cid, bool uplink, const uint8_t *payload, int len) {
    if (cid == 0x06 && uplink && len == 2) {
        uint8_t batt = payload[0];
        int8_t margin = (int8_t)(payload[1] & 0x3F);
        if (margin & 0x20) margin -= 64; // sign-extend 6-bit field
        String battStr;
        if (batt == 0) battStr = "connected to external power";
        else if (batt == 255) battStr = "battery level unknown";
        else battStr = String(batt) + "/254 (~" + String((batt * 100) / 254) + "%)";
        return "device reporting status: battery " + battStr + ", demod margin " +
               (margin >= 0 ? "+" : "") + String(margin) + " dB.";
    }
    if (cid == 0x02 && uplink) return "device requesting the network to report link margin and gateway count.";
    if (cid == 0x02 && !uplink && len == 2) {
        return "network reporting link margin " + String(payload[0]) + " dB, seen by " +
               String(payload[1]) + " gateway(s).";
    }
    if (cid == 0x03 && uplink) return "device acknowledging an ADR (data-rate/power) change from the network.";
    if (cid == 0x03 && !uplink) return "network setting this device's data rate, TX power and channel mask.";
    if (cid == 0x04 && uplink) return "device acknowledging a duty-cycle limit.";
    if (cid == 0x04 && !uplink) return "network limiting this device's duty cycle.";
    if (cid == 0x05 && uplink) return "device acknowledging new RX1/RX2 window parameters.";
    if (cid == 0x05 && !uplink) return "network reconfiguring this device's RX1/RX2 windows.";
    if (cid == 0x06 && !uplink) return "network polling this device's battery level and demod margin.";
    if (cid == 0x07 && uplink) return "device acknowledging a new/modified uplink channel.";
    if (cid == 0x07 && !uplink) return "network defining or modifying an uplink channel.";
    if (cid == 0x08 && uplink) return "device acknowledging an RX1-delay change.";
    if (cid == 0x08 && !uplink) return "network adjusting this device's RX1 delay.";
    if (cid == 0x09 && uplink) return "device acknowledging max-EIRP / dwell-time limits.";
    if (cid == 0x09 && !uplink) return "network setting max EIRP and/or dwell-time limits.";
    if (cid == 0x0A && uplink) return "device acknowledging a downlink channel change.";
    if (cid == 0x0A && !uplink) return "network moving a downlink channel's frequency.";
    if (cid == 0x0D && uplink) return "device requesting the current network time.";
    if (cid == 0x0D && !uplink) return "network reporting the current GPS time.";
    return "MAC command (raw payload " + hexBytes(payload, len < 0 ? 0 : (size_t)len) + ").";
}

} // namespace

LoRaWANFrame parseLoRaWANFrame(const uint8_t *data, size_t len) {
    LoRaWANFrame f;

    if (len < 1) {
        f.parseNote = "empty buffer - cannot even read MHDR";
        return f;
    }

    f.valid = true;
    f.mhdr = data[0];
    uint8_t mtypeBits = f.mhdr >> 5;
    f.major = f.mhdr & 0x03;
    f.mtype = (mtypeBits <= 7) ? (LoRaWANMType)mtypeBits : LoRaWANMType::Proprietary;

    switch (f.mtype) {
    case LoRaWANMType::JoinRequest:
        f.mtypeName = "Join Request";
        f.mtypeDescription = "a device attempting to join a network.";
        f.isJoinRequest = true;
        break;
    case LoRaWANMType::JoinAccept:
        f.mtypeName = "Join Accept";
        f.mtypeDescription =
            "the network accepting a join request. Body is encrypted with the device's root "
            "key - passive recon cannot decode it.";
        break;
    case LoRaWANMType::UnconfirmedDataUp:
        f.mtypeName = "Unconfirmed Data Up";
        f.mtypeDescription = "a device sending data upstream without requesting an acknowledgment.";
        f.isDataFrame = true;
        f.isUplink = true;
        break;
    case LoRaWANMType::UnconfirmedDataDown:
        f.mtypeName = "Unconfirmed Data Down";
        f.mtypeDescription = "the network sending data downstream without requesting an acknowledgment.";
        f.isDataFrame = true;
        f.isUplink = false;
        break;
    case LoRaWANMType::ConfirmedDataUp:
        f.mtypeName = "Confirmed Data Up";
        f.mtypeDescription = "a device sending data upstream and requesting an acknowledgment.";
        f.isDataFrame = true;
        f.isUplink = true;
        break;
    case LoRaWANMType::ConfirmedDataDown:
        f.mtypeName = "Confirmed Data Down";
        f.mtypeDescription = "the network sending data downstream and requesting an acknowledgment.";
        f.isDataFrame = true;
        f.isUplink = false;
        break;
    case LoRaWANMType::RejoinRequest:
        f.mtypeName = "Rejoin Request";
        f.mtypeDescription = "a device re-establishing its session with the network.";
        break;
    case LoRaWANMType::Proprietary:
        f.mtypeName = "Proprietary";
        f.mtypeDescription = "a vendor-specific frame format - not decoded further.";
        break;
    }

    if (f.mtype == LoRaWANMType::Proprietary) {
        // Explicitly stop here per spec: identify only, no further decode attempt.
        return f;
    }

    if (f.isJoinRequest) {
        constexpr size_t JOIN_LEN = 1 + 8 + 8 + 2 + 4; // MHDR+JoinEUI+DevEUI+DevNonce+MIC
        if (len < JOIN_LEN) {
            f.truncated = true;
            f.parseNote = "truncated join request (" + String((unsigned)len) + "/" +
                           String((unsigned)JOIN_LEN) + " bytes) - fields past the cut are unavailable";
            // Still surface whatever fully-present fields we can, best-effort.
        }
        if (len >= 9) {
            for (int i = 0; i < 8; i++) f.joinEUI[i] = data[8 - i]; // reverse LE -> display order
        }
        if (len >= 17) {
            for (int i = 0; i < 8; i++) f.devEUI[i] = data[16 - i];
        }
        if (len >= 19) { f.devNonce = data[17] | (data[18] << 8); }
        if (len >= JOIN_LEN) {
            memcpy(f.mic, data + 19, 4);
            f.micPresent = true;
        }
        return f;
    }

    // Data frame (Unconfirmed/Confirmed Up/Down) or Rejoin-Request. Rejoin
    // has a variable, rejoin-type-dependent layout in real LoRaWAN 1.1 that
    // we don't attempt here - identify it and stop, same as Proprietary.
    if (f.mtype == LoRaWANMType::RejoinRequest) { return f; }

    constexpr size_t MIN_DATA_HDR = 1 + 4 + 1 + 2; // MHDR+DevAddr+FCtrl+FCnt
    if (len < MIN_DATA_HDR) {
        f.truncated = true;
        f.parseNote = "truncated data frame (" + String((unsigned)len) + "/" + String((unsigned)MIN_DATA_HDR) +
                       " bytes minimum) - cannot read a full FHDR";
        return f;
    }

    f.devAddr = ((uint32_t)data[4] << 24) | ((uint32_t)data[3] << 16) | ((uint32_t)data[2] << 8) | data[1];
    f.fctrl = data[5];
    f.adr = f.fctrl & 0x80;
    f.adrAckReq = f.fctrl & 0x40;
    f.ack = f.fctrl & 0x20;
    f.classBOrFPending = f.fctrl & 0x10;
    f.foptsLen = f.fctrl & 0x0F;
    f.fcnt = data[6] | (data[7] << 8);

    const size_t foptsStart = MIN_DATA_HDR;
    const size_t headerLen = MIN_DATA_HDR + f.foptsLen;
    if (len < headerLen) {
        f.truncated = true;
        f.foptsTruncated = true;
        f.parseNote = "FOpts truncated (FOptsLen=" + String(f.foptsLen) + " but only " +
                       String((unsigned)(len - foptsStart)) + " byte(s) remain)";
        return f;
    }

    // Decode FOpts MAC commands (1.0.x plaintext). Never read past foptsStart+foptsLen.
    size_t pos = foptsStart;
    const size_t foptsEnd = foptsStart + f.foptsLen;
    while (pos < foptsEnd) {
        uint8_t cid = data[pos];
        const MacCidInfo *info = findCidInfo(cid);
        int expectedLen = info ? (f.isUplink ? info->upLen : info->dnLen) : -1;
        const char *name = info ? (f.isUplink ? info->upName : info->dnName) : nullptr;

        if (!info || expectedLen < 0) {
            // Unknown CID - in 1.1 FOpts are encrypted and will look like
            // garbage; we can't tell "unknown command" from "encrypted" from
            // a single frame, so surface it plainly rather than guessing.
            LoRaWANMacCommand cmd;
            cmd.cid = cid;
            cmd.name = "CID 0x" + hexByte(cid);
            cmd.description = "unrecognized MAC command CID (or FOpts encrypted, as in LoRaWAN 1.1) - "
                               "cannot decode further.";
            f.macCommands.push_back(cmd);
            pos += 1; // can't know its real length; stop to avoid misreading the rest
            f.foptsTruncated = true;
            break;
        }

        if (pos + 1 + (size_t)expectedLen > foptsEnd) {
            f.foptsTruncated = true;
            f.truncated = true;
            f.parseNote = "FOpts command " + String(name) + " needs " + String(expectedLen) +
                           " byte(s) but FOpts region ends first";
            break;
        }

        LoRaWANMacCommand cmd;
        cmd.cid = cid;
        cmd.name = name;
        cmd.description = describeMacCommandPayload(cid, f.isUplink, data + pos + 1, expectedLen);
        f.macCommands.push_back(cmd);
        pos += 1 + expectedLen;
    }

    size_t remaining = len - headerLen;
    if (remaining >= 4) {
        size_t micStart = len - 4;
        memcpy(f.mic, data + micStart, 4);
        f.micPresent = true;

        size_t frmLen = micStart - headerLen;
        if (frmLen > 0) {
            f.hasFPort = true;
            f.fport = data[headerLen];
            f.frmPayloadPtr = data + headerLen + 1;
            f.frmPayloadLen = frmLen - 1;
        }
    } else {
        f.truncated = true;
        f.parseNote = "frame ends before a 4-byte MIC could be read";
    }

    return f;
}

String loRaWANOperatorHint(uint32_t devAddr) {
    uint8_t top = (devAddr >> 24) & 0xFF;
    if (top <= 0x01) return "Private network / ChirpStack-typical range (best-effort)";
    if (top >= 0x20 && top <= 0x27) return "The Things Network - TTN (best-effort)";
    if (top >= 0x60 && top <= 0x6F) return "Helium (legacy, best-effort)";
    if (top == 0xFC) return "Actility (best-effort)";
    return "";
}

String loRaWANDevEuiOuiHint(const uint8_t devEUI[8]) {
    // Deliberately sparse - only IEEE/Semtech-documented ranges are listed
    // here, not guessed vendor OUIs, so a wrong attribution is never shown
    // as if it were fact. Extend with verified IEEE OUI assignments only.
    if (devEUI[0] == 0xFE && devEUI[1] == 0xFF && (devEUI[2] == 0xFF || devEUI[2] == 0xFE)) {
        return "reserved test/development DevEUI range (no real OUI assigned)";
    }
    return "";
}

std::vector<String> describeLoRaWANFrame(const LoRaWANFrame &frame) {
    std::vector<String> lines;

    if (!frame.valid) {
        lines.push_back("Unparseable frame: " + frame.parseNote);
        return lines;
    }

    lines.push_back(frame.mtypeName + " - " + frame.mtypeDescription);

    if (frame.mtype == LoRaWANMType::Proprietary || frame.mtype == LoRaWANMType::RejoinRequest ||
        frame.mtype == LoRaWANMType::JoinAccept) {
        return lines;
    }

    if (frame.isJoinRequest) {
        char buf[96];
        String ouiHint = loRaWANDevEuiOuiHint(frame.devEUI);
        snprintf(
            buf, sizeof(buf), "DevEUI %s - the device's globally-unique hardware ID (OUI %02X:%02X:%02X%s%s).",
            hexBytes(frame.devEUI, 8).c_str(), frame.devEUI[0], frame.devEUI[1], frame.devEUI[2],
            ouiHint.length() ? ", " : "", ouiHint.c_str()
        );
        if (frame.devEUI[0] || frame.devEUI[1] || frame.devEUI[2] || frame.devEUI[3] || frame.devEUI[4] ||
            frame.devEUI[5] || frame.devEUI[6] || frame.devEUI[7])
            lines.push_back(String(buf));
        lines.push_back(
            "JoinEUI " + hexBytes(frame.joinEUI, 8) + " - the join/network server the device is targeting."
        );
        char nonceBuf[24];
        snprintf(nonceBuf, sizeof(nonceBuf), "0x%04X (%u)", frame.devNonce, frame.devNonce);
        lines.push_back(
            "DevNonce " + String(nonceBuf) +
            " - anti-replay nonce; a repeat for the same DevEUI would flag a replayed join."
        );
        if (frame.anomalyReplayedDevNonce) {
            lines.push_back("! Anomaly: this DevNonce was seen before from the same DevEUI - possible replay.");
        }
        if (frame.truncated) lines.push_back("(note: " + frame.parseNote + ")");
        return lines;
    }

    // Data frame
    char addrBuf[16];
    snprintf(addrBuf, sizeof(addrBuf), "0x%08lX", (unsigned long)frame.devAddr);
    String addrLine = "DevAddr " + String(addrBuf);
    String hint = loRaWANOperatorHint(frame.devAddr);
    if (hint.length()) addrLine += " (" + hint + ")";
    lines.push_back(addrLine + ".");

    String flagsLine;
    if (frame.adr) flagsLine += "ADR on - the network manages this device's data rate and TX power. ";
    if (frame.adrAckReq)
        flagsLine += "ADRACKReq set - device asking the network to confirm the link is still alive. ";
    if (frame.ack) flagsLine += "ACK - this frame acknowledges a previous downlink. ";
    if (frame.classBOrFPending)
        flagsLine += frame.isUplink ? "Class B beaconing enabled on this device. "
                                     : "FPending - the network has more downlink data queued. ";
    if (flagsLine.length()) lines.push_back(flagsLine);

    lines.push_back("FCnt " + String(frame.fcnt) + " (frame counter; gaps between captures usually mean "
                                                     "missed packets).");
    if (frame.anomalyFcntRegression) {
        lines.push_back("! Anomaly: FCnt went backwards vs. a previous frame from this DevAddr.");
    }

    for (const auto &cmd : frame.macCommands) {
        lines.push_back("MAC command " + cmd.name + " - " + cmd.description);
    }
    if (frame.foptsTruncated) lines.push_back("(note: FOpts region truncated or unrecognized mid-way)");

    if (frame.hasFPort) {
        lines.push_back(
            "FPort " + String(frame.fport) + " - " + String((unsigned)frame.frmPayloadLen) +
            " byte(s) of encrypted application payload (not decoded)."
        );
    }

    if (frame.truncated) lines.push_back("(note: " + frame.parseNote + ")");

    return lines;
}

// ---------------------------------------------------------------------------
// Self-test: Appendix A vectors (bruce-lora-recon-TASK.md)
// ---------------------------------------------------------------------------
namespace {

bool g_selfTestFailed = false;

void expectTrue(bool cond, const char *what) {
    if (!cond) {
        Serial.printf("[LoRaWANParser][FAIL] %s\n", what);
        g_selfTestFailed = true;
    }
}

template <typename T> void expectEqual(T actual, T expected, const char *what) {
    if (actual != expected) {
        Serial.print("[LoRaWANParser][FAIL] ");
        Serial.print(what);
        Serial.print(" expected=");
        Serial.print(expected);
        Serial.print(" actual=");
        Serial.println(actual);
        g_selfTestFailed = true;
    }
}

void expectStrEqual(const String &actual, const String &expected, const char *what) {
    if (actual != expected) {
        Serial.printf(
            "[LoRaWANParser][FAIL] %s expected=\"%s\" actual=\"%s\"\n", what, expected.c_str(), actual.c_str()
        );
        g_selfTestFailed = true;
    }
}

// TV_JOIN_REQ: 23 bytes
const uint8_t TV_JOIN_REQ[] = {
    0x00,                                            // MHDR: Join-Request
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // JoinEUI (LE) -> 0000000000000000
    0x04, 0x03, 0x02, 0x01, 0x00, 0x41, 0x40, 0xA8,  // DevEUI  (LE) -> A840410001020304
    0x2A, 0x1B,                                      // DevNonce(LE) -> 0x1B2A
    0xDE, 0xAD, 0xBE, 0xEF                           // MIC (placeholder)
};

// TV_UNCONF_UP: 20 bytes
const uint8_t TV_UNCONF_UP[] = {
    0x40,                   // MHDR: Unconfirmed Data Up
    0x34, 0x12, 0x0B, 0x26, // DevAddr (LE) -> 0x260B1234
    0x83,                   // FCtrl: ADR=1, FOptsLen=3
    0x64, 0x00,             // FCnt (LE) -> 100
    0x06, 0xC8, 0x0A,       // FOpts: DevStatusAns batt=200 margin=+10
    0x01,                   // FPort 1
    0x11, 0x22, 0x33, 0x44, // FRMPayload (encrypted, 4B)
    0xCA, 0xFE, 0xF0, 0x0D  // MIC (placeholder)
};

// TV_CONF_UP: 18 bytes
const uint8_t TV_CONF_UP[] = {
    0x80,                         // MHDR: Confirmed Data Up
    0x42, 0x00, 0xFE, 0x01,       // DevAddr (LE) -> 0x01FE0042
    0xC0,                         // FCtrl: ADR=1, ADRACKReq=1, FOptsLen=0
    0x00, 0x10,                   // FCnt (LE) -> 4096
    0x02,                         // FPort 2
    0xAB, 0xCD, 0xEF, 0x01, 0x23, // FRMPayload (encrypted, 5B)
    0x12, 0x34, 0x56, 0x78        // MIC (placeholder)
};

void testJoinRequest() {
    LoRaWANFrame f = parseLoRaWANFrame(TV_JOIN_REQ, sizeof(TV_JOIN_REQ));
    expectTrue(f.valid, "join: valid");
    expectTrue(f.isJoinRequest, "join: isJoinRequest");
    expectEqual((int)f.mtype, (int)LoRaWANMType::JoinRequest, "join: mtype");
    expectEqual<int>(f.major, 0, "join: major");
    expectStrEqual(hexBytes(f.joinEUI, 8), "0000000000000000", "join: JoinEUI display");
    expectStrEqual(hexBytes(f.devEUI, 8), "A840410001020304", "join: DevEUI display");
    expectEqual<int>(f.devNonce, 0x1B2A, "join: DevNonce");
    expectTrue(f.micPresent, "join: micPresent");
    uint8_t expectedMic[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    expectTrue(memcmp(f.mic, expectedMic, 4) == 0, "join: MIC bytes (read only, not validated)");

    auto lines = describeLoRaWANFrame(f);
    bool sawType = false, sawDevEUI = false, sawJoinEUI = false, sawNonce = false;
    for (auto &l : lines) {
        if (l.indexOf("Join Request") >= 0) sawType = true;
        if (l.indexOf("A840410001020304") >= 0) sawDevEUI = true;
        if (l.indexOf("0000000000000000") >= 0) sawJoinEUI = true;
        if (l.indexOf("1B2A") >= 0) sawNonce = true;
    }
    expectTrue(sawType, "join: description mentions Join Request");
    expectTrue(sawDevEUI, "join: description mentions DevEUI");
    expectTrue(sawJoinEUI, "join: description mentions JoinEUI");
    expectTrue(sawNonce, "join: description mentions DevNonce");
}

void testUnconfirmedUp() {
    LoRaWANFrame f = parseLoRaWANFrame(TV_UNCONF_UP, sizeof(TV_UNCONF_UP));
    expectTrue(f.valid, "unconf-up: valid");
    expectTrue(f.isDataFrame, "unconf-up: isDataFrame");
    expectTrue(f.isUplink, "unconf-up: isUplink");
    expectEqual((int)f.mtype, (int)LoRaWANMType::UnconfirmedDataUp, "unconf-up: mtype");
    expectEqual<uint32_t>(f.devAddr, 0x260B1234, "unconf-up: DevAddr");
    expectTrue(f.adr, "unconf-up: ADR bit");
    expectTrue(!f.adrAckReq, "unconf-up: ADRACKReq bit");
    expectTrue(!f.ack, "unconf-up: ACK bit");
    expectEqual<int>(f.foptsLen, 3, "unconf-up: FOptsLen");
    expectEqual<int>(f.fcnt, 100, "unconf-up: FCnt");
    expectEqual<size_t>(f.macCommands.size(), 1, "unconf-up: FOpts command count");
    if (f.macCommands.size() == 1) {
        expectEqual<int>(f.macCommands[0].cid, 0x06, "unconf-up: FOpts CID");
        expectStrEqual(f.macCommands[0].name, "DevStatusAns", "unconf-up: FOpts name");
    }
    expectTrue(f.hasFPort, "unconf-up: hasFPort");
    expectEqual<int>(f.fport, 1, "unconf-up: FPort");
    expectEqual<size_t>(f.frmPayloadLen, 4, "unconf-up: FRMPayload length");
    expectTrue(f.frmPayloadPtr != nullptr, "unconf-up: FRMPayload pointer set");
    if (f.frmPayloadPtr) expectStrEqual(hexBytes(f.frmPayloadPtr, 4), "11223344", "unconf-up: FRMPayload raw hex");
    expectTrue(f.micPresent, "unconf-up: micPresent");

    auto lines = describeLoRaWANFrame(f);
    bool sawType = false, sawAddr = false, sawAdr = false, sawFcnt = false, sawStatus = false, sawFport = false;
    for (auto &l : lines) {
        if (l.indexOf("Unconfirmed Data Up") >= 0) sawType = true;
        if (l.indexOf("260B1234") >= 0) sawAddr = true;
        if (l.indexOf("ADR on") >= 0) sawAdr = true;
        if (l.indexOf("FCnt 100") >= 0) sawFcnt = true;
        if (l.indexOf("DevStatusAns") >= 0 && l.indexOf("200/254") >= 0 && l.indexOf("+10") >= 0) sawStatus = true;
        if (l.indexOf("FPort 1") >= 0 && l.indexOf("4 byte") >= 0) sawFport = true;
    }
    expectTrue(sawType, "unconf-up: description mentions type");
    expectTrue(sawAddr, "unconf-up: description mentions DevAddr");
    expectTrue(sawAdr, "unconf-up: description mentions ADR");
    expectTrue(sawFcnt, "unconf-up: description mentions FCnt");
    expectTrue(sawStatus, "unconf-up: description mentions DevStatusAns detail");
    expectTrue(sawFport, "unconf-up: description mentions FPort + payload size");
}

void testConfirmedUp() {
    LoRaWANFrame f = parseLoRaWANFrame(TV_CONF_UP, sizeof(TV_CONF_UP));
    expectTrue(f.valid, "conf-up: valid");
    expectEqual((int)f.mtype, (int)LoRaWANMType::ConfirmedDataUp, "conf-up: mtype");
    expectEqual<uint32_t>(f.devAddr, 0x01FE0042, "conf-up: DevAddr");
    expectTrue(f.adr, "conf-up: ADR bit");
    expectTrue(f.adrAckReq, "conf-up: ADRACKReq bit");
    expectEqual<int>(f.foptsLen, 0, "conf-up: FOptsLen");
    expectEqual<size_t>(f.macCommands.size(), 0, "conf-up: no FOpts commands");
    expectEqual<int>(f.fcnt, 4096, "conf-up: FCnt");
    expectTrue(f.hasFPort, "conf-up: hasFPort");
    expectEqual<int>(f.fport, 2, "conf-up: FPort");
    expectEqual<size_t>(f.frmPayloadLen, 5, "conf-up: FRMPayload length");
    if (f.frmPayloadPtr)
        expectStrEqual(hexBytes(f.frmPayloadPtr, 5), "ABCDEF0123", "conf-up: FRMPayload raw hex");
    expectTrue(f.micPresent, "conf-up: micPresent");

    auto lines = describeLoRaWANFrame(f);
    bool sawType = false, sawAddr = false, sawAdrReq = false, sawFcnt = false, sawFport = false;
    for (auto &l : lines) {
        if (l.indexOf("Confirmed Data Up") >= 0) sawType = true;
        if (l.indexOf("01FE0042") >= 0) sawAddr = true;
        if (l.indexOf("ADRACKReq") >= 0) sawAdrReq = true;
        if (l.indexOf("FCnt 4096") >= 0) sawFcnt = true;
        if (l.indexOf("FPort 2") >= 0 && l.indexOf("5 byte") >= 0) sawFport = true;
    }
    expectTrue(sawType, "conf-up: description mentions type");
    expectTrue(sawAddr, "conf-up: description mentions DevAddr");
    expectTrue(sawAdrReq, "conf-up: description mentions ADRACKReq");
    expectTrue(sawFcnt, "conf-up: description mentions FCnt");
    expectTrue(sawFport, "conf-up: description mentions FPort + payload size");
}

void testEdgeCases() {
    // Truncated data frame (6 bytes - not even a full FHDR).
    const uint8_t truncatedData[] = {0x40, 0x34, 0x12, 0x0B, 0x26, 0x83};
    LoRaWANFrame f1 = parseLoRaWANFrame(truncatedData, sizeof(truncatedData));
    expectTrue(f1.valid, "truncated-data: MHDR still read (valid)");
    expectTrue(f1.truncated, "truncated-data: flagged truncated");
    expectTrue(f1.parseNote.length() > 0, "truncated-data: has a parse note");

    // Truncated join request (< 23 bytes).
    const uint8_t truncatedJoin[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    LoRaWANFrame f2 = parseLoRaWANFrame(truncatedJoin, sizeof(truncatedJoin));
    expectTrue(f2.valid, "truncated-join: MHDR still read (valid)");
    expectTrue(f2.truncated, "truncated-join: flagged truncated");

    // Proprietary frame (MHDR 0xE0 -> MType 7).
    const uint8_t proprietary[] = {0xE0, 0xAA, 0xBB, 0xCC};
    LoRaWANFrame f3 = parseLoRaWANFrame(proprietary, sizeof(proprietary));
    expectTrue(f3.valid, "proprietary: valid");
    expectEqual((int)f3.mtype, (int)LoRaWANMType::Proprietary, "proprietary: mtype");
    expectTrue(!f3.truncated, "proprietary: not flagged truncated (identified and stopped, by design)");
    auto lines = describeLoRaWANFrame(f3);
    expectTrue(lines.size() == 1, "proprietary: description is identify-and-stop (one line)");

    // Empty buffer must not crash.
    LoRaWANFrame f4 = parseLoRaWANFrame(nullptr, 0);
    expectTrue(!f4.valid, "empty: not valid");
}

} // namespace

bool runLoRaWANParserSelfTest() {
    g_selfTestFailed = false;
    Serial.println("[LoRaWANParser] running self-test (synthetic vectors, no radio traffic)...");

    testJoinRequest();
    testUnconfirmedUp();
    testConfirmedUp();
    testEdgeCases();

    Serial.println(
        g_selfTestFailed ? "[LoRaWANParser] SELF-TEST FAILED - see [FAIL] lines above"
                          : "[LoRaWANParser] self-test PASSED (join-request, unconfirmed-up, "
                            "confirmed-up, truncated + proprietary edge cases)"
    );
    return !g_selfTestFailed;
}
#endif
