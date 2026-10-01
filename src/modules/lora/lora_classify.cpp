#include "lora_classify.h"
#if !defined(LITE_VERSION)

#include "lora_meshcore.h"
#include <Arduino.h>
#include <string.h>

namespace loramp {

const char *protoName(Proto p) {
    switch (p) {
    case LP_MESHTASTIC: return "MT";
    case LP_MESHCORE: return "MC";
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

    // MeshCore lives on sync 0x12. Adverts are plaintext - decode the layout.
    if (ctx.syncWord == 0x12) {
        mcore::Frame mf;
        if (mcore::parse(buf, (uint8_t)(len > 255 ? 255 : len), mf)) {
            out.proto = LP_MESHCORE;
            mcore::Advert adv;
            if (mcore::parseAdvert(mf, adv)) {
                out.mcId = (uint32_t)adv.pubkey[0] | ((uint32_t)adv.pubkey[1] << 8) |
                           ((uint32_t)adv.pubkey[2] << 16) | ((uint32_t)adv.pubkey[3] << 24);
                out.mcNodeType = adv.nodeType;
                if (adv.hasName) strlcpy(out.mcName, adv.name, sizeof(out.mcName));
                if (adv.hasLatLon) {
                    out.hasPos = true;
                    out.lat = adv.latE6 / 1e6;
                    out.lon = adv.lonE6 / 1e6;
                }
                // Bad-clock flag: advert timestamp (unix secs) wildly off a sane
                // floor (2023-01-01). A zero clock on our side can't judge, so we
                // only flag an implausibly small/zero stamp here.
                out.mcBadClock = (adv.timestamp != 0 && adv.timestamp < 1672531200UL);
            }
            return out.proto;
        }
        return out.proto = LP_UNKNOWN;
    }

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
    } else if (c.proto == LP_MESHCORE) {
        if (c.mcName[0])
            snprintf(out, cap, "MC !%08x advert %s", (unsigned)c.mcId, c.mcName);
        else if (c.mcId)
            snprintf(out, cap, "MC !%08x advert", (unsigned)c.mcId);
        else
            snprintf(out, cap, "MC frame");
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
    Serial.printf("[LoRaMP] self-test MT %s: proto=%s name=\"%s\" sum=\"%s\"\n", ok ? "PASS" : "FAIL",
                  protoName(p), c.mtName, sum);

    // MeshCore advert: header(route=FLOOD,type=ADVERT,v0) + pathlen(0) +
    // pubkey[32] + ts[4] + sig[64] + flags(name|chat) + name.
    const char *mcName = "MC-Repeater";
    uint8_t mc[2 + 32 + 4 + 64 + 1 + 16];
    size_t o = 0;
    mc[o++] = (uint8_t)((0 << 6) | (4 << 2) | 1); // version0, type ADVERT(4), route FLOOD(1)
    mc[o++] = 0x00;                               // hashSize=1, hops=0
    for (int i = 0; i < 32; i++) mc[o++] = (uint8_t)(0xA0 + i);          // pubkey (id = A0 A1 A2 A3)
    mc[o++] = 0x00; mc[o++] = 0x1C; mc[o++] = 0x61; mc[o++] = 0x65;      // ts ~2023+ (LE)
    for (int i = 0; i < 64; i++) mc[o++] = 0;                            // signature (unchecked)
    mc[o++] = 0x80 | mcore::NODE_REPEATER;                              // flags: name + repeater
    size_t nlen = strlen(mcName);
    memcpy(mc + o, mcName, nlen);
    o += nlen;

    RadioCtx mctx = {869.618f, 8, 0x12};
    Classified mc_c;
    Proto mp = classify(mc, o, mctx, nullptr, 0, -55, 6.0f, mc_c);
    bool mcOk = (mp == LP_MESHCORE) && (strcmp(mc_c.mcName, mcName) == 0) &&
                (mc_c.mcId == 0xA3A2A1A0) && (mc_c.mcNodeType == mcore::NODE_REPEATER);
    char msum[80];
    summary(mc_c, msum, sizeof(msum));
    Serial.printf("[LoRaMP] self-test MC %s: proto=%s name=\"%s\" sum=\"%s\"\n", mcOk ? "PASS" : "FAIL",
                  protoName(mp), mc_c.mcName, msum);

    return ok && mcOk;
}

} // namespace loramp

#endif
