#include "lora_classify.h"
#if !defined(LITE_VERSION)

#include <Arduino.h>
#include <string.h>

namespace loramp {

const char *protoName(Proto p) {
    switch (p) {
    case LP_MESHTASTIC: return "MT";
    case LP_LORAWAN: return "LoRaWAN";
    default: return "?";
    }
}

// Meshtastic uses sync word 0x2B; LoRaWAN uses 0x34. The classifier prefers the
// network that lives on the radio config the frame arrived on, then falls back
// to a structural check.
Proto classify(const uint8_t *buf, size_t len, const RadioCtx &ctx, const uint8_t *key, size_t keyLen,
               int8_t rssi, float snr, Classified &out) {
    out = Classified{};
    out.rssi = rssi;
    out.snr = snr;

    if (!buf || len == 0) return out.proto = LP_UNKNOWN;

    // LoRaWAN lives on sync 0x34; its own sweep/parser (LoRaRecon) owns deep
    // decode. Here we only tag it so a frame heard on that config is attributed.
    if (ctx.syncWord == 0x34) return out.proto = LP_LORAWAN;

    // Meshtastic: a 16-byte header must unpack, and (for LongFast) the channel
    // hash must match. Reuses the fork's MeshtasticCodec - no new decoder.
    meshtastic::PacketHeader hdr;
    if (meshtastic::unpackHeader(buf, len, hdr)) {
        if (hdr.channel == meshtastic::LONGFAST_CHANNEL_HASH) {
            out.proto = LP_MESHTASTIC;
            out.mt = hdr;

            size_t ctLen = len - meshtastic::HEADER_LEN;
            if (key && keyLen && ctLen > 0 && ctLen <= meshtastic::MAX_PLAINTEXT) {
                uint8_t pt[meshtastic::MAX_PLAINTEXT];
                memcpy(pt, buf + meshtastic::HEADER_LEN, ctLen);
                uint8_t nonce[16];
                meshtastic::initNonce(hdr.from, hdr.id, nonce);
                meshtastic::aesCtrCrypt(key, nonce, pt, ctLen);

                meshtastic::DataMsg dm;
                if (meshtastic::decodeData(pt, ctLen, dm)) {
                    out.mtDecrypted = true;
                    out.mtPortnum = dm.portnum;
                    if (dm.portnum == meshtastic::NODEINFO_APP) {
                        char shortName[8] = {0};
                        meshtastic::decodeUserName(
                            dm.payload, dm.payloadLen, out.mtName, sizeof(out.mtName), shortName,
                            sizeof(shortName)
                        );
                    }
                    // POSITION lat/lon decode deferred to Phase 2 (verify field
                    // numbers against position.proto before trusting them).
                }
            }
            return out.proto;
        }
    }
    return out.proto = LP_UNKNOWN;
}

void summary(const Classified &c, char *out, size_t cap) {
    if (!out || cap == 0) return;
    if (c.proto == LP_MESHTASTIC) {
        const char *port = c.mtDecrypted
                               ? (c.mtPortnum == meshtastic::NODEINFO_APP   ? "NODEINFO"
                                  : c.mtPortnum == meshtastic::POSITION_APP ? "POSITION"
                                  : c.mtPortnum == meshtastic::TEXT_MESSAGE_APP
                                      ? "TEXT"
                                      : "DATA")
                               : "enc";
        if (c.mtName[0])
            snprintf(out, cap, "MT !%08x hop%u/%u %s %s", (unsigned)c.mt.from, c.mt.hopLimit(),
                     c.mt.hopStart(), port, c.mtName);
        else
            snprintf(out, cap, "MT !%08x hop%u/%u %s", (unsigned)c.mt.from, c.mt.hopLimit(),
                     c.mt.hopStart(), port);
    } else if (c.proto == LP_LORAWAN) {
        snprintf(out, cap, "LoRaWAN frame (see LoRaWAN sweep)");
    } else {
        snprintf(out, cap, "? unknown LoRa frame");
    }
}

// ── Offline self-test ─────────────────────────────────────────────────────────
// Builds a real Meshtastic NODEINFO frame with the codec (pack header, encode
// User->Data, AES-CTR with the LongFast key) and asserts the classifier decodes
// the name back. Headless-verifiable over serial, like runMeshtasticSelfTest().
bool runLoraMultiSelfTest() {
    Serial.println("[LoRaMP] self-test: classify Meshtastic NODEINFO frame");
    uint8_t key[16];
    size_t keyLen = 0;
    meshtastic::expandPsk(1, key, keyLen); // LongFast default channel key

    // Build a User protobuf -> Data{NODEINFO} -> ciphertext.
    const char *id = "!1a2b3c4d", *lname = "Squatch-Base", *sname = "SqB";
    uint8_t user[96];
    size_t userLen = meshtastic::encodeUser(id, lname, sname, user, sizeof(user));
    uint8_t data[128];
    size_t dataLen = meshtastic::encodeData(meshtastic::NODEINFO_APP, user, userLen, data, sizeof(data));
    if (userLen == 0 || dataLen == 0) {
        Serial.println("[LoRaMP] self-test FAIL: encode");
        return false;
    }

    meshtastic::PacketHeader hdr;
    hdr.from = 0x1a2b3c4d;
    hdr.to = meshtastic::BROADCAST_ADDR;
    hdr.id = 0x00c0ffee;
    hdr.channel = meshtastic::LONGFAST_CHANNEL_HASH;
    hdr.flags = meshtastic::PacketHeader::makeFlags(3, false, 3);

    uint8_t frame[meshtastic::HEADER_LEN + 128];
    meshtastic::packHeader(hdr, frame);
    memcpy(frame + meshtastic::HEADER_LEN, data, dataLen);
    uint8_t nonce[16];
    meshtastic::initNonce(hdr.from, hdr.id, nonce);
    meshtastic::aesCtrCrypt(key, nonce, frame + meshtastic::HEADER_LEN, dataLen);
    size_t frameLen = meshtastic::HEADER_LEN + dataLen;

    RadioCtx ctx = {869.525f, 11, 0x2B};
    Classified c;
    Proto p = classify(frame, frameLen, ctx, key, keyLen, -42, 7.5f, c);

    bool ok = (p == LP_MESHTASTIC) && c.mtDecrypted && (c.mtPortnum == meshtastic::NODEINFO_APP) &&
              (strcmp(c.mtName, lname) == 0) && (c.mt.from == hdr.from) && (c.mt.hopLimit() == 3);
    char sum[80];
    summary(c, sum, sizeof(sum));
    Serial.printf("[LoRaMP] self-test %s: proto=%s name=\"%s\" sum=\"%s\"\n", ok ? "PASS" : "FAIL",
                  protoName(p), c.mtName, sum);
    return ok;
}

} // namespace loramp

#endif
