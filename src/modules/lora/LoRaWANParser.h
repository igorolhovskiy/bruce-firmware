#ifndef __LORAWAN_PARSER_H__
#define __LORAWAN_PARSER_H__
#if !defined(LITE_VERSION)

#include <Arduino.h>
#include <vector>

// Passive-recon LoRaWAN PHY payload decoder. Decodes only what is
// obtainable without keys: MHDR/DevAddr/FCtrl/FCnt/FOpts (1.0.x plaintext)/
// FPort/JoinEUI/DevEUI/DevNonce. FRMPayload is AES-encrypted application
// data and is never "decoded" - only its length/pointer are kept. MIC bytes
// are extracted but their validity can never be asserted (that needs the
// device's session/network key, which passive recon does not have).

enum class LoRaWANMType : uint8_t {
    JoinRequest = 0,
    JoinAccept = 1,
    UnconfirmedDataUp = 2,
    UnconfirmedDataDown = 3,
    ConfirmedDataUp = 4,
    ConfirmedDataDown = 5,
    RejoinRequest = 6,
    Proprietary = 7,
};

struct LoRaWANMacCommand {
    uint8_t cid = 0;
    String name;        // e.g. "DevStatusAns"
    String description; // plain-English, includes decoded values when known
};

struct LoRaWANFrame {
    bool valid = false;     // false only when even the MHDR can't be read
    bool truncated = false; // buffer ended before the MType's fields did
    String parseNote;       // human-readable reason when valid=false/truncated

    uint8_t mhdr = 0;
    LoRaWANMType mtype = LoRaWANMType::Proprietary;
    uint8_t major = 0;
    String mtypeName;
    String mtypeDescription;

    bool isJoinRequest = false;
    bool isDataFrame = false;
    bool isUplink = false; // meaningful only when isDataFrame

    // Join request fields (reversed from LE wire order to the conventional
    // big-endian display order, per §8 of the task brief).
    uint8_t joinEUI[8] = {0};
    uint8_t devEUI[8] = {0};
    uint16_t devNonce = 0;

    // Data frame fields
    uint32_t devAddr = 0;
    uint8_t fctrl = 0;
    bool adr = false;
    bool adrAckReq = false;
    bool ack = false;
    bool classBOrFPending = false;
    uint8_t foptsLen = 0;
    uint16_t fcnt = 0;
    std::vector<LoRaWANMacCommand> macCommands;
    bool foptsTruncated = false;

    bool hasFPort = false;
    uint8_t fport = 0;
    size_t frmPayloadLen = 0;
    const uint8_t *frmPayloadPtr = nullptr; // points into caller's buffer; opaque, never decoded

    bool micPresent = false;
    uint8_t mic[4] = {0};

    // Cross-frame anomaly hints - set by the caller (a small per-DevAddr/DevEUI
    // tracker), never by parseLoRaWANFrame() itself, since a single frame
    // carries no history.
    bool anomalyReplayedDevNonce = false;
    bool anomalyFcntRegression = false;
};

// Parses a raw LoRaWAN PHY payload (MHDR..MIC as received off the air).
// Never reads past `len` bytes. Truncated or unparseable input is flagged
// via `truncated`/`valid`, never a crash or an out-of-bounds read.
LoRaWANFrame parseLoRaWANFrame(const uint8_t *data, size_t len);

// Best-effort (NetID-type) operator hint from a DevAddr's top byte. Returns
// "" when no hint applies. Illustrative only - never asserted in tests.
String loRaWANOperatorHint(uint32_t devAddr);

// Builds the human-readable detail lines for a parsed frame (protocol
// fields only; RF metrics like RSSI/link-margin are added by the caller).
std::vector<String> describeLoRaWANFrame(const LoRaWANFrame &frame);

// Feeds the Appendix A hex vectors (plus truncated/proprietary edge cases)
// through the decoder and asserts the decoded output. Prints PASS/FAIL per
// vector and a summary to Serial. Returns true iff every assertion passed.
// Requires no radio traffic - safe to run every time Recon is opened.
bool runLoRaWANParserSelfTest();

#endif
#endif
