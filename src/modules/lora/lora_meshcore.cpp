#include "lora_meshcore.h"
#if !defined(LITE_VERSION)

#include <string.h>

namespace mcore {

static uint16_t rd16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

const char *nodeTypeName(uint8_t t) {
    switch (t) {
    case NODE_CHAT: return "chat";
    case NODE_REPEATER: return "rptr";
    case NODE_ROOM: return "room";
    case NODE_SENSOR: return "sens";
    default: return "?";
    }
}

bool parse(const uint8_t *d, uint8_t len, Frame &f) {
    memset(&f, 0, sizeof f);
    if (len < 2) return false;
    const uint8_t h = d[0];
    f.route = h & 0x03;
    f.type = (h >> 2) & 0x0F;
    f.version = h >> 6;
    if (f.version != 0) return false;
    size_t off = 1;
    if (f.route == ROUTE_TRANSPORT_FLOOD || f.route == ROUTE_TRANSPORT_DIRECT) {
        if (len < 6) return false;
        f.hasTransport = true;
        off = 5; // 2x uint16 transport addresses
    }
    if (off >= len) return false;
    const uint8_t pl = d[off++];
    f.hashSize = (uint8_t)((pl >> 6) + 1);
    f.hops = pl & 0x3F;
    if (f.hashSize > 2) return false; // 3 is reserved
    const size_t pathBytes = (size_t)f.hops * f.hashSize;
    if (pathBytes > 64 || off + pathBytes > len) return false;
    off += pathBytes;
    f.payload = d + off;
    f.payloadLen = (uint8_t)(len - off);
    (void)rd16le; // transport fields parsed structurally; values unused here
    return true;
}

bool parseAdvert(const Frame &f, Advert &a) {
    memset(&a, 0, sizeof a);
    if (f.type != TYPE_ADVERT || f.payloadLen < 32 + 4 + 64 + 1) return false;
    const uint8_t *p = f.payload;
    memcpy(a.pubkey, p, 32);
    a.timestamp = rd32le(p + 32);
    // signature p[36..99] carried but not checked
    const uint8_t flags = p[100];
    a.nodeType = flags & 0x0F;
    size_t off = 101;
    const size_t end = f.payloadLen;
    if (flags & 0x10) {
        if (off + 8 > end) return false;
        a.hasLatLon = true;
        a.latE6 = (int32_t)rd32le(p + off);
        a.lonE6 = (int32_t)rd32le(p + off + 4);
        off += 8;
    }
    if (flags & 0x20) {
        if (off + 2 > end) return false;
        off += 2;
    }
    if (flags & 0x40) {
        if (off + 2 > end) return false;
        off += 2;
    }
    if (flags & 0x80) {
        a.hasName = true;
        size_t n = end - off;
        if (n > sizeof a.name - 1) n = sizeof a.name - 1;
        memcpy(a.name, p + off, n);
        a.name[n] = '\0';
    }
    return true;
}

} // namespace mcore

#endif
