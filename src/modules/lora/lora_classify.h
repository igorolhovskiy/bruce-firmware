#ifndef __LORA_CLASSIFY_H__
#define __LORA_CLASSIFY_H__
#if !defined(LITE_VERSION)

#include "MeshtasticCodec.h"
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Multi-protocol LoRa frame classifier (Phase 1: Meshtastic + LoRaWAN + raw).
// Pure logic: given the on-air bytes and the radio settings they arrived on,
// decide which network a frame belongs to and pull out the plaintext metadata
// a passive listener may legitimately read. No radio, no display - unit-tested
// offline via runLoraMultiSelfTest(). See bruce-lora-multiproto-TASK.md.
//
// Protocol decoders are reused from the fork's own code (MeshtasticCodec,
// LoRaWANParser); the classifier only routes. Design cues (per-network
// listening plan, node flags) are adapted from skizzophrenic/SquachWatch-CYD
// (GPL-3.0, AGPL-compatible via section 13).
// ---------------------------------------------------------------------------

namespace loramp {

enum Proto : uint8_t {
    LP_UNKNOWN = 0, // received, but no decoder claimed it (still a sighting)
    LP_MESHTASTIC,
    LP_LORAWAN,
};

const char *protoName(Proto p); // "MT", "LoRaWAN", "?"

// What radio config a frame was heard on - lets the classifier prefer the
// network that lives there (Meshtastic sync 0x2B vs LoRaWAN sync 0x34).
struct RadioCtx {
    float freqMHz;
    uint8_t sf;
    uint8_t syncWord;
};

// Result of classifying one frame. For Meshtastic, `mt` holds the decoded
// header and (if the LongFast key worked) the decrypted Data portnum/name.
struct Classified {
    Proto proto = LP_UNKNOWN;
    // Meshtastic fields (valid when proto == LP_MESHTASTIC)
    meshtastic::PacketHeader mt;
    bool mtDecrypted = false;    // LongFast key decoded a Data message
    uint32_t mtPortnum = 0;      // decoded portnum, if mtDecrypted
    char mtName[20] = {0};       // node long-name, if a NODEINFO frame
    double lat = 0, lon = 0;     // if a POSITION frame
    bool hasPos = false;
    int8_t rssi = 0;
    float snr = 0;
};

// Classify one received frame. `key`/`keyLen` is the Meshtastic channel key to
// try (the expanded LongFast default key); pass nullptr to skip decryption.
// Returns the Proto (also set in out.proto).
Proto classify(const uint8_t *buf, size_t len, const RadioCtx &ctx, const uint8_t *key, size_t keyLen,
               int8_t rssi, float snr, Classified &out);

// One-line summary for the FRAMES list and the serial mirror, e.g.
//   "MT !3b1c9a2e hop2/3 NODEINFO Squatch-Base"
// Never longer than cap-1; always NUL-terminated.
void summary(const Classified &c, char *out, size_t cap);

// Offline self-test: builds canned frames with the codecs and asserts the
// classifier/decoders agree. Mirrors to Serial. Returns true on pass.
bool runLoraMultiSelfTest();

} // namespace loramp

#endif
#endif // __LORA_CLASSIFY_H__
