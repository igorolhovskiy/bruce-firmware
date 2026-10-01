#ifndef __LORA_MESHCORE_H__
#define __LORA_MESHCORE_H__
#if !defined(LITE_VERSION)

#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Minimal MeshCore frame + advert parser (layout only; the Ed25519 signature is
// carried, not checked, and encrypted payloads are left shut). Ported from
// skizzophrenic/SquachWatch-CYD lora_meshcore.{h,cpp} (GPL-3.0, AGPL-compatible
// via section 13). Pure logic - no radio/display, unit-testable.
// ---------------------------------------------------------------------------

namespace mcore {

enum Route : uint8_t { ROUTE_TRANSPORT_FLOOD = 0, ROUTE_FLOOD = 1, ROUTE_DIRECT = 2, ROUTE_TRANSPORT_DIRECT = 3 };
enum Type : uint8_t { TYPE_ADVERT = 4 }; // the one type Phase 2a decodes
enum NodeType : uint8_t { NODE_CHAT = 1, NODE_REPEATER = 2, NODE_ROOM = 3, NODE_SENSOR = 4 };
const char *nodeTypeName(uint8_t t);

struct Frame {
    uint8_t route, type, version;
    bool hasTransport;
    uint8_t hashSize, hops;
    const uint8_t *payload;
    uint8_t payloadLen;
};

struct Advert {
    uint8_t pubkey[32];
    uint32_t timestamp;
    uint8_t nodeType;
    bool hasLatLon;
    int32_t latE6, lonE6;
    bool hasName;
    char name[33];
};

// Parse the outer frame header. Returns false on a malformed/foreign frame.
bool parse(const uint8_t *d, uint8_t len, Frame &f);

// Parse an ADVERT payload (pubkey, timestamp, node type, optional lat/lon+name).
bool parseAdvert(const Frame &f, Advert &a);

} // namespace mcore

#endif
#endif // __LORA_MESHCORE_H__
