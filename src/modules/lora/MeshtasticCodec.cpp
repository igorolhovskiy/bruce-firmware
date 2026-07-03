#if !defined(LITE_VERSION)
#include "MeshtasticCodec.h"
#include <mbedtls/aes.h>
#include <string.h>

namespace meshtastic {

namespace {

// The well-known default channel key (PSK index 1). Re-derived from the
// Meshtastic firmware definition (Channels.h `defaultpsk[]`), not copied.
const uint8_t kDefaultPsk[DEFAULT_KEY_LEN] = {0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                              0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01};

uint32_t readLE32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
void writeLE32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

// Read a base-128 varint with bounds checking. Returns false on truncation or
// an over-long (> 5-byte, i.e. > 32-bit) encoding. Advances *pos on success.
bool readVarint(const uint8_t *buf, size_t len, size_t *pos, uint32_t *out) {
    uint32_t result = 0;
    int shift = 0;
    size_t i = *pos;
    while (i < len) {
        uint8_t b = buf[i++];
        result |= (uint32_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *out = result;
            *pos = i;
            return true;
        }
        shift += 7;
        if (shift >= 35) return false; // more than 5 bytes -> not a valid uint32 varint
    }
    return false; // ran off the end
}

size_t writeVarint(uint8_t *out, size_t cap, size_t pos, uint32_t v) {
    while (v >= 0x80) {
        if (pos >= cap) return 0;
        out[pos++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    if (pos >= cap) return 0;
    out[pos++] = (uint8_t)v;
    return pos;
}

} // namespace

bool unpackHeader(const uint8_t *buf, size_t len, PacketHeader &out) {
    if (buf == nullptr || len < HEADER_LEN) return false;
    out.to = readLE32(buf + 0);
    out.from = readLE32(buf + 4);
    out.id = readLE32(buf + 8);
    out.flags = buf[12];
    out.channel = buf[13];
    out.next_hop = buf[14];
    out.relay_node = buf[15];
    return true;
}

void packHeader(const PacketHeader &h, uint8_t out[HEADER_LEN]) {
    writeLE32(out + 0, h.to);
    writeLE32(out + 4, h.from);
    writeLE32(out + 8, h.id);
    out[12] = h.flags;
    out[13] = h.channel;
    out[14] = h.next_hop;
    out[15] = h.relay_node;
}

void expandPsk(uint8_t index, uint8_t keyOut[16], size_t &keyLenOut) {
    if (index == 0) {
        keyLenOut = 0; // encryption disabled
        return;
    }
    memcpy(keyOut, kDefaultPsk, DEFAULT_KEY_LEN);
    keyOut[DEFAULT_KEY_LEN - 1] = (uint8_t)(keyOut[DEFAULT_KEY_LEN - 1] + index - 1);
    keyLenOut = DEFAULT_KEY_LEN;
}

uint8_t channelHash(const char *name, const uint8_t *key, size_t keyLen) {
    uint8_t h = 0;
    for (const char *p = name; p && *p; p++) h ^= (uint8_t)*p;
    for (size_t i = 0; i < keyLen; i++) h ^= key[i];
    return h;
}

void initNonce(uint32_t fromNode, uint32_t packetId, uint8_t nonce[16]) {
    memset(nonce, 0, 16);
    // packetId occupies the low 8 bytes as a uint64 LE; our id is 32-bit so the
    // high 4 bytes stay zero. fromNode occupies the next 4 bytes LE.
    writeLE32(nonce + 0, packetId);
    writeLE32(nonce + 8, fromNode);
}

void aesCtrCrypt(const uint8_t key[16], const uint8_t nonce[16], uint8_t *data, size_t len) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128); // CTR uses the encrypt schedule for both directions

    uint8_t nc[16];
    memcpy(nc, nonce, 16); // crypt_ctr mutates the counter in place; keep caller's nonce intact
    uint8_t streamBlock[16] = {0};
    size_t ncOff = 0;
    mbedtls_aes_crypt_ctr(&ctx, len, &ncOff, nc, streamBlock, data, data);
    mbedtls_aes_free(&ctx);
}

size_t encodeData(uint32_t portnum, const uint8_t *payload, size_t payloadLen, uint8_t *out, size_t outCap) {
    size_t pos = 0;
    // field 1 (portnum), wire type 0 (varint): tag = (1<<3)|0 = 0x08
    if (pos >= outCap) return 0;
    out[pos++] = 0x08;
    pos = writeVarint(out, outCap, pos, portnum);
    if (pos == 0) return 0;
    // field 2 (payload), wire type 2 (length-delimited): tag = (2<<3)|2 = 0x12
    if (payloadLen > 0 || payload != nullptr) {
        if (pos >= outCap) return 0;
        out[pos++] = 0x12;
        pos = writeVarint(out, outCap, pos, (uint32_t)payloadLen);
        if (pos == 0) return 0;
        if (pos + payloadLen > outCap) return 0;
        memcpy(out + pos, payload, payloadLen);
        pos += payloadLen;
    }
    return pos;
}

bool decodeData(const uint8_t *buf, size_t len, DataMsg &out) {
    out.portnum = 0;
    out.payloadLen = 0;
    out.valid = false;
    size_t pos = 0;
    while (pos < len) {
        uint32_t tag;
        if (!readVarint(buf, len, &pos, &tag)) return false;
        uint32_t field = tag >> 3;
        uint32_t wire = tag & 0x07;
        switch (wire) {
        case 0: { // varint
            uint32_t v;
            if (!readVarint(buf, len, &pos, &v)) return false;
            if (field == 1) out.portnum = v;
            break;
        }
        case 2: { // length-delimited
            uint32_t l;
            if (!readVarint(buf, len, &pos, &l)) return false;
            if (pos + l > len) return false; // would over-read
            if (field == 2) {
                size_t copyLen = l > MAX_DATA_PAYLOAD ? MAX_DATA_PAYLOAD : l;
                memcpy(out.payload, buf + pos, copyLen);
                out.payloadLen = copyLen;
            }
            pos += l;
            break;
        }
        case 5: // 32-bit
            if (pos + 4 > len) return false;
            pos += 4;
            break;
        case 1: // 64-bit
            if (pos + 8 > len) return false;
            pos += 8;
            break;
        default: // 3,4 (groups, deprecated) or invalid -> undecodable
            return false;
        }
    }
    out.valid = true;
    return true;
}

bool decodeUserName(const uint8_t *buf, size_t len, char *longName, size_t longCap, char *shortName,
                    size_t shortCap) {
    if (longCap) longName[0] = 0;
    if (shortCap) shortName[0] = 0;
    bool found = false;
    size_t pos = 0;
    while (pos < len) {
        uint32_t tag;
        if (!readVarint(buf, len, &pos, &tag)) return false;
        uint32_t field = tag >> 3;
        uint32_t wire = tag & 0x07;
        switch (wire) {
        case 0: {
            uint32_t v;
            if (!readVarint(buf, len, &pos, &v)) return false;
            break;
        }
        case 2: {
            uint32_t l;
            if (!readVarint(buf, len, &pos, &l)) return false;
            if (pos + l > len) return false;
            if (field == 2 && longCap) { // long_name
                size_t n = l < longCap - 1 ? l : longCap - 1;
                memcpy(longName, buf + pos, n);
                longName[n] = 0;
                found = true;
            } else if (field == 3 && shortCap) { // short_name
                size_t n = l < shortCap - 1 ? l : shortCap - 1;
                memcpy(shortName, buf + pos, n);
                shortName[n] = 0;
                found = true;
            }
            pos += l;
            break;
        }
        case 5:
            if (pos + 4 > len) return false;
            pos += 4;
            break;
        case 1:
            if (pos + 8 > len) return false;
            pos += 8;
            break;
        default:
            return false;
        }
    }
    return found;
}

bool sanitizeDisplayText(const uint8_t *payload, size_t len, String &out) {
    out = "";
    out.reserve(len + 1);
    size_t i = 0;
    while (i < len) {
        uint8_t b = payload[i];
        if (b < 0x80) { // ASCII range
            if (b == '\n' || b == '\r' || b == '\t') {
                out += ' '; // keep on one line, keep the CSV field single-line
                i++;
            } else if (b < 0x20 || b == 0x7F) {
                return false; // C0 control / DEL -> binary, not a text message
            } else {
                out += (char)b; // printable ASCII kept verbatim
                i++;
            }
        } else { // UTF-8 multi-byte lead: validate the whole sequence
            size_t seqLen;
            if ((b & 0xE0) == 0xC0) seqLen = 2;
            else if ((b & 0xF0) == 0xE0) seqLen = 3;
            else if ((b & 0xF8) == 0xF0) seqLen = 4;
            else return false; // continuation byte as lead, or > 4-byte form: malformed
            if (i + seqLen > len) return false; // truncated sequence
            for (size_t j = 1; j < seqLen; j++)
                if ((payload[i + j] & 0xC0) != 0x80) return false; // bad continuation byte
            out += '?'; // valid code point the device font can't render -> placeholder
            i += seqLen;
        }
    }
    return true;
}

uint32_t DutyCycle::usedMs(uint32_t now) const {
    uint32_t sum = 0;
    for (size_t i = 0; i < count; i++) {
        size_t idx = (head + CAP - count + i) % CAP;
        if ((uint32_t)(now - atMs[idx]) < windowMs) sum += airMs[idx];
    }
    return sum;
}

void DutyCycle::record(uint32_t now, uint32_t air) {
    atMs[head] = now;
    airMs[head] = air;
    head = (head + 1) % CAP;
    if (count < CAP) count++;
}

uint32_t DutyCycle::msUntilAvailable(uint32_t now, uint32_t newAirMs) const {
    uint32_t used = usedMs(now);
    if (used + newAirMs <= budgetMs) return 0;
    uint32_t needToShed = used + newAirMs - budgetMs;
    // Walk records oldest-first; once we have shed enough, the time until that
    // record leaves the window is how long the caller must wait.
    uint32_t shed = 0;
    for (size_t i = 0; i < count; i++) {
        size_t idx = (head + CAP - count + i) % CAP;
        uint32_t age = (uint32_t)(now - atMs[idx]);
        if (age >= windowMs) continue; // already out of window
        shed += airMs[idx];
        if (shed >= needToShed) return windowMs - age; // this record expiring frees enough
    }
    return windowMs; // shouldn't happen if newAirMs <= budgetMs
}

// ---------------------------------------------------------------------------
// Appendix A self-test. All vectors are either hand-verifiable (protobuf,
// hash, nonce, header) or generated with reference tooling (the two AES-CTR
// ciphertexts came from `openssl enc -aes-128-ctr`, not hand-guessed).
// ---------------------------------------------------------------------------

namespace {

bool bytesEq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n) == 0; }

void logCase(const char *name, bool ok) {
    Serial.printf("[Meshtastic] self-test %-22s %s\n", name, ok ? "PASS" : "FAIL");
}

} // namespace

bool runMeshtasticSelfTest() {
    bool allOk = true;
    Serial.println("[Meshtastic] --- codec/crypto self-test ---");

    // A.1 Data protobuf encode/decode
    {
        const uint8_t expect[] = {0x08, 0x01, 0x12, 0x02, 0x68, 0x69}; // portnum=1, "hi"
        uint8_t enc[64];
        size_t n = encodeData(TEXT_MESSAGE_APP, (const uint8_t *)"hi", 2, enc, sizeof(enc));
        bool ok = (n == sizeof(expect)) && bytesEq(enc, expect, n);
        DataMsg dm;
        ok = ok && decodeData(expect, sizeof(expect), dm) && dm.portnum == 1 && dm.payloadLen == 2 &&
             bytesEq(dm.payload, (const uint8_t *)"hi", 2);
        // empty payload round-trips (portnum only)
        DataMsg dm2;
        ok = ok && decodeData((const uint8_t *)"\x08\x01", 2, dm2) && dm2.portnum == 1 && dm2.payloadLen == 0;
        // trailing unknown field (field 3 varint: 18 01) is ignored, portnum+payload still returned
        const uint8_t withUnknown[] = {0x08, 0x01, 0x12, 0x02, 0x68, 0x69, 0x18, 0x01};
        DataMsg dm3;
        ok = ok && decodeData(withUnknown, sizeof(withUnknown), dm3) && dm3.portnum == 1 &&
             dm3.payloadLen == 2 && bytesEq(dm3.payload, (const uint8_t *)"hi", 2);
        logCase("protobuf(hi)", ok);
        allOk &= ok;
    }

    // A.2 default key PSK expansion
    {
        uint8_t k[16];
        size_t kl = 0;
        expandPsk(1, k, kl);
        bool ok = kl == 16 && bytesEq(k, kDefaultPsk, 16);
        expandPsk(2, k, kl); // same but last byte 0x02
        ok = ok && kl == 16 && bytesEq(k, kDefaultPsk, 15) && k[15] == 0x02;
        size_t kl0 = 99;
        uint8_t k0[16];
        expandPsk(0, k0, kl0);
        ok = ok && kl0 == 0;
        logCase("psk-expand", ok);
        allOk &= ok;
    }

    // A.3 channel hash for LongFast + default key == 0x08
    {
        uint8_t h = channelHash("LongFast", kDefaultPsk, 16);
        bool ok = h == LONGFAST_CHANNEL_HASH;
        logCase("channel-hash=0x08", ok);
        allOk &= ok;
    }

    // A.4 AES-CTR round-trip + reference KATs (openssl-generated)
    {
        // nonce for id=0x0000ABCD, from=0x12345678
        uint8_t nonce[16];
        initNonce(0x12345678u, 0x0000ABCDu, nonce);
        const uint8_t expectNonce[] = {0xcd, 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00};
        bool ok = bytesEq(nonce, expectNonce, 16);

        // Single-block KAT: pt 08 01 12 02 68 69 -> ct 4d 75 77 d5 e0 02
        uint8_t buf[64];
        const uint8_t pt1[] = {0x08, 0x01, 0x12, 0x02, 0x68, 0x69};
        const uint8_t ct1[] = {0x4d, 0x75, 0x77, 0xd5, 0xe0, 0x02};
        memcpy(buf, pt1, sizeof(pt1));
        aesCtrCrypt(kDefaultPsk, nonce, buf, sizeof(pt1));
        ok = ok && bytesEq(buf, ct1, sizeof(ct1));   // encrypt matches reference
        aesCtrCrypt(kDefaultPsk, nonce, buf, sizeof(pt1));
        ok = ok && bytesEq(buf, pt1, sizeof(pt1));   // decrypt round-trips

        // Multi-block KAT (21 bytes, crosses the 16-byte block boundary):
        // pt "08 01 12 11 Hello Meshtastic!" -> ct 4d7577c6c00e0100bb3e87cbe91c868e5769652ac0
        const uint8_t pt2[] = {0x08, 0x01, 0x12, 0x11, 'H', 'e', 'l', 'l', 'o', ' ', 'M',
                               'e',  's',  'h',  't',  'a', 's', 't', 'i', 'c', '!'};
        const uint8_t ct2[] = {0x4d, 0x75, 0x77, 0xc6, 0xc0, 0x0e, 0x01, 0x00, 0xbb, 0x3e, 0x87,
                               0xcb, 0xe9, 0x1c, 0x86, 0x8e, 0x57, 0x69, 0x65, 0x2a, 0xc0};
        memcpy(buf, pt2, sizeof(pt2));
        aesCtrCrypt(kDefaultPsk, nonce, buf, sizeof(pt2));
        ok = ok && bytesEq(buf, ct2, sizeof(ct2));   // boundary-crossing matches reference
        aesCtrCrypt(kDefaultPsk, nonce, buf, sizeof(pt2));
        ok = ok && bytesEq(buf, pt2, sizeof(pt2));
        logCase("aes-ctr KAT", ok);
        allOk &= ok;
    }

    // A.5 header pack/unpack + truncation rejection
    {
        PacketHeader h;
        h.to = BROADCAST_ADDR;
        h.from = 0x12345678u;
        h.id = 0x0000ABCDu;
        h.flags = PacketHeader::makeFlags(3, false, 0);
        h.channel = LONGFAST_CHANNEL_HASH;
        uint8_t packed[16];
        packHeader(h, packed);
        const uint8_t expect[] = {0xff, 0xff, 0xff, 0xff, 0x78, 0x56, 0x34, 0x12,
                                  0xcd, 0xab, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00};
        bool ok = bytesEq(packed, expect, 16);
        PacketHeader h2;
        ok = ok && unpackHeader(packed, 16, h2) && h2.to == h.to && h2.from == h.from && h2.id == h.id &&
             h2.flags == h.flags && h2.channel == h.channel && h2.hopLimit() == 3;
        // 10-byte (too short) buffer must be rejected, no over-read
        PacketHeader h3;
        ok = ok && !unpackHeader(packed, 10, h3);
        logCase("header pack/unpack", ok);
        allOk &= ok;
    }

    // Negative: truncated protobuf (length-delimited claims more than present)
    {
        const uint8_t truncated[] = {0x08, 0x01, 0x12, 0x05, 0x68, 0x69}; // says 5-byte payload, only 2
        DataMsg dm;
        bool ok = !decodeData(truncated, sizeof(truncated), dm); // rejected, no crash/over-read
        // non-text portnum surfaces by number, not as text (portnum 3)
        const uint8_t posMsg[] = {0x08, 0x03, 0x12, 0x02, 0xAA, 0xBB};
        DataMsg dm2;
        ok = ok && decodeData(posMsg, sizeof(posMsg), dm2) && dm2.portnum == POSITION_APP;
        logCase("negative/edge", ok);
        allOk &= ok;
    }

    // Full originate->receive loopback: Data -> encrypt -> header+ct on the TX
    // side, then unpack -> decrypt -> decode on the RX side, round-trips exactly.
    {
        uint8_t key[16];
        size_t kl = 0;
        expandPsk(1, key, kl);
        const char *msg = "loopback!";
        size_t mlen = strlen(msg);
        uint8_t data[64];
        size_t dl = encodeData(TEXT_MESSAGE_APP, (const uint8_t *)msg, mlen, data, sizeof(data));
        uint32_t from = 0xDEADBEEFu, id = 0x01020304u;
        uint8_t nonce[16];
        initNonce(from, id, nonce);
        aesCtrCrypt(key, nonce, data, dl);
        uint8_t frame[16 + 64];
        PacketHeader h;
        h.to = BROADCAST_ADDR;
        h.from = from;
        h.id = id;
        h.flags = PacketHeader::makeFlags(3, false, 3);
        h.channel = LONGFAST_CHANNEL_HASH;
        packHeader(h, frame);
        memcpy(frame + 16, data, dl);
        size_t flen = 16 + dl;

        PacketHeader rh;
        bool ok = unpackHeader(frame, flen, rh) && rh.channel == LONGFAST_CHANNEL_HASH &&
                  rh.from == from && rh.id == id && rh.hopLimit() == 3;
        size_t ctl = flen - 16;
        uint8_t pt[64];
        memcpy(pt, frame + 16, ctl);
        uint8_t n2[16];
        initNonce(rh.from, rh.id, n2);
        aesCtrCrypt(key, n2, pt, ctl);
        DataMsg dm;
        ok = ok && decodeData(pt, ctl, dm) && dm.portnum == TEXT_MESSAGE_APP && dm.payloadLen == mlen &&
             bytesEq(dm.payload, (const uint8_t *)msg, mlen);
        logCase("tx loopback", ok);
        allOk &= ok;
    }

    // NODEINFO User name decode (long_name field 2, short_name field 3)
    {
        // User{ id="!12345678", long_name="Test Node", short_name="TN" }
        const uint8_t user[] = {0x0a, 0x09, '!', '1', '2', '3', '4', '5', '6', '7', '8', 0x12, 0x09,
                                'T',  'e',  's', 't', ' ', 'N', 'o', 'd', 'e', 0x1a, 0x02, 'T', 'N'};
        char ln[40], sn[8];
        bool ok = decodeUserName(user, sizeof(user), ln, sizeof(ln), sn, sizeof(sn)) &&
                  strcmp(ln, "Test Node") == 0 && strcmp(sn, "TN") == 0;
        // truncated User payload rejected without over-read
        const uint8_t bad[] = {0x12, 0x09, 'T', 'e', 's', 't'};
        char ln2[40], sn2[8];
        ok = ok && !decodeUserName(bad, sizeof(bad), ln2, sizeof(ln2), sn2, sizeof(sn2));
        logCase("nodeinfo name", ok);
        allOk &= ok;
    }

    // Displayable-text guard: plain ASCII passes verbatim; emoji/accents become
    // '?'; a mis-routed NODEINFO User protobuf (has C0 control bytes) is rejected.
    {
        String s;
        bool ok = sanitizeDisplayText((const uint8_t *)"hi there", 8, s) && s == "hi there";
        // "waza" + U+1F1EB U+1F1F7 (flag, two 4-byte code points) + "74" -> "waza??74"
        const uint8_t emoji[] = {'w',  'a',  'z',  'a',  0xf0, 0x9f, 0x87, 0xab,
                                 0xf0, 0x9f, 0x87, 0xb7, '7',  '4'};
        String s2;
        ok = ok && sanitizeDisplayText(emoji, sizeof(emoji), s2) && s2 == "waza??74";
        // real NODEINFO User payload (starts 0a 09 ... has 0x12 control byte) -> rejected
        const uint8_t user[] = {0x0a, 0x09, '!', '1', '2', '3', '4', '5', '6', '7', '8', 0x12, 0x02, 'T', 'N'};
        String s3;
        ok = ok && !sanitizeDisplayText(user, sizeof(user), s3);
        // truncated UTF-8 sequence (lead byte, no continuation) -> rejected
        const uint8_t trunc[] = {'a', 0xf0, 0x9f};
        String s4;
        ok = ok && !sanitizeDisplayText(trunc, sizeof(trunc), s4);
        // newline/tab collapse to a space (stays one CSV line / one display row)
        String s5;
        ok = ok && sanitizeDisplayText((const uint8_t *)"a\nb\tc", 5, s5) && s5 == "a b c";
        logCase("text guard", ok);
        allOk &= ok;
    }

    // Duty-cycle accounting (deterministic, synthetic timing)
    {
        DutyCycle dc;
        dc.windowMs = 10000; // 10 s window
        dc.budgetMs = 1000;  // 1 s budget (10%)
        bool ok = dc.usedMs(0) == 0 && !dc.wouldExceed(0, 500);
        dc.record(0, 500);
        dc.record(100, 400); // used = 900 within window
        ok = ok && dc.usedMs(200) == 900;
        ok = ok && !dc.wouldExceed(200, 100);  // 900+100 == 1000, allowed
        ok = ok && dc.wouldExceed(200, 200);   // 900+200 > 1000, blocked
        // wait until the first (500ms @ t=0) record leaves the 10s window
        uint32_t wait = dc.msUntilAvailable(200, 200); // need to shed >=100 -> first rec frees 500
        ok = ok && wait == (10000 - 200);
        // after the window fully passes, budget is clear again
        ok = ok && dc.usedMs(11000) == 0 && !dc.wouldExceed(11000, 1000);
        logCase("duty-cycle", ok);
        allOk &= ok;
    }

    Serial.printf("[Meshtastic] self-test %s\n", allOk ? "PASSED" : "FAILED");
    return allOk;
}

} // namespace meshtastic
#endif
