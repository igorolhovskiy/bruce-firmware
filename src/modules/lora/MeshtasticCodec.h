#ifndef __MESHTASTIC_CODEC_H__
#define __MESHTASTIC_CODEC_H__
#if !defined(LITE_VERSION)
#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Meshtastic on-air codec + crypto (leaf/client, LongFast default channel).
//
// Pure data-plane: header pack/unpack, PSK expansion, channel hash, AES-CTR
// nonce, AES-128-CTR (mbedtls), and a minimal `Data` protobuf encode/decode.
// No radio, no display - so it is unit-testable offline (runMeshtasticSelfTest).
//
// Constants anchored to Meshtastic firmware v2.7.26; see docs/meshtastic-notes.md.
// Meshtastic firmware is GPL-3.0 and its protobufs Apache-2.0; the small constants
// re-derived here (default PSK, channel-hash algorithm, nonce layout, wire tags)
// are kept AGPL-compatible by re-derivation + attribution rather than file copy.
// ---------------------------------------------------------------------------

namespace meshtastic {

constexpr size_t HEADER_LEN = 16;
constexpr uint32_t BROADCAST_ADDR = 0xFFFFFFFFu;
constexpr uint8_t LONGFAST_CHANNEL_HASH = 0x08; // xorHash("LongFast") ^ xorHash(defaultpsk)
constexpr size_t MAX_DATA_PAYLOAD = 237;        // Meshtastic max Data payload
constexpr size_t MAX_PLAINTEXT = 240;
constexpr size_t DEFAULT_KEY_LEN = 16;          // AES-128

// PortNum values we distinguish (portnums.proto). Others are shown by number.
enum PortNum : uint32_t {
    UNKNOWN_APP = 0,
    TEXT_MESSAGE_APP = 1,
    POSITION_APP = 3,
    NODEINFO_APP = 4,
    ROUTING_APP = 5,
};

// PacketHeader flag layout (RadioInterface.h): bits0-2 hop_limit, bit3 want_ack,
// bit4 via_mqtt, bits5-7 hop_start.
struct PacketHeader {
    uint32_t to = 0;
    uint32_t from = 0;
    uint32_t id = 0;
    uint8_t flags = 0;
    uint8_t channel = 0;
    uint8_t next_hop = 0;
    uint8_t relay_node = 0;

    uint8_t hopLimit() const { return flags & 0x07; }
    bool wantAck() const { return (flags & 0x08) != 0; }
    bool viaMqtt() const { return (flags & 0x10) != 0; }
    uint8_t hopStart() const { return (flags >> 5) & 0x07; }
    static uint8_t makeFlags(uint8_t hopLimit, bool wantAck, uint8_t hopStart) {
        return (hopLimit & 0x07) | (wantAck ? 0x08 : 0) | ((hopStart & 0x07) << 5);
    }
};

// Header <-> 16 little-endian bytes. unpack returns false if len < HEADER_LEN.
bool unpackHeader(const uint8_t *buf, size_t len, PacketHeader &out);
void packHeader(const PacketHeader &h, uint8_t out[HEADER_LEN]);

// Expand a 1-byte PSK index into a full key. index 0 => keyLen 0 (no encryption);
// index 1 => the well-known default key; index N => default key with last byte
// += (N-1). keyOut must hold >= 16 bytes.
void expandPsk(uint8_t index, uint8_t keyOut[16], size_t &keyLenOut);

// Single-byte channel hash = XOR-of-all-bytes(name) ^ XOR-of-all-bytes(key).
uint8_t channelHash(const char *name, const uint8_t *key, size_t keyLen);

// 16-byte AES-CTR IV/counter block: packetId(uint64 LE, low 8) | fromNode(LE, 4) | 0000.
void initNonce(uint32_t fromNode, uint32_t packetId, uint8_t nonce[16]);

// AES-128-CTR in place (encrypt == decrypt). `nonce` is not modified (copied
// internally). Byte-compatible with Meshtastic for any realistic packet size.
void aesCtrCrypt(const uint8_t key[16], const uint8_t nonce[16], uint8_t *data, size_t len);

// Minimal `Data` protobuf. Encode: field1 portnum (varint) + field2 payload
// (length-delimited). Returns encoded length, or 0 on overflow.
size_t encodeData(uint32_t portnum, const uint8_t *payload, size_t payloadLen, uint8_t *out, size_t outCap);

// Rolling-window airtime accounting for the EU868 10% duty-cycle limit. Pure
// and testable (all timing is passed in). Window/budget default to 1 hour / 10%.
struct DutyCycle {
    static constexpr size_t CAP = 64;
    uint32_t atMs[CAP] = {0};
    uint32_t airMs[CAP] = {0};
    size_t count = 0; // number of valid records (ring, oldest evicted at CAP)
    size_t head = 0;  // next write slot
    uint32_t windowMs = 3600000UL;
    uint32_t budgetMs = 360000UL; // 10% of the window

    void reset() {
        count = 0;
        head = 0;
    }
    // Sum of airtime whose records still fall inside the rolling window at `now`.
    uint32_t usedMs(uint32_t now) const;
    bool wouldExceed(uint32_t now, uint32_t newAirMs) const { return usedMs(now) + newAirMs > budgetMs; }
    void record(uint32_t now, uint32_t airMs);
    // ms until enough in-window airtime ages out to admit newAirMs (0 if OK now).
    uint32_t msUntilAvailable(uint32_t now, uint32_t newAirMs) const;
};

struct DataMsg {
    uint32_t portnum = 0;
    uint8_t payload[MAX_DATA_PAYLOAD] = {0};
    size_t payloadLen = 0;
    bool valid = false; // parsed without over-read / malformed structure
};
// Decode field1 (portnum) + field2 (payload); skip unknown fields gracefully.
// Returns false on any truncation / bad wire type (out.valid also cleared).
bool decodeData(const uint8_t *buf, size_t len, DataMsg &out);

// Deterministic Appendix-A self-test (no radio). Logs each sub-result to serial.
bool runMeshtasticSelfTest();

} // namespace meshtastic

#endif
#endif
