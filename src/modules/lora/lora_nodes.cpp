#include "lora_nodes.h"
#if !defined(LITE_VERSION)

#include <string.h>

namespace loramp {

// Flags derivable from a single Meshtastic header. Richer flags (duty-cycle,
// frame-counter resets, bad clock) need cross-frame state / other protocols and
// land in later phases.
static uint8_t flagsFromHeader(const meshtastic::PacketHeader &h) {
    uint8_t f = 0;
    if (h.hopStart() > 3) f |= NF_HOPS_HIGH;
    if (h.viaMqtt()) f |= NF_MQTT;
    if (h.hopStart() == 0) f |= NF_OLD_FW;
    return f;
}

size_t NodeTable::evictOldest() {
    size_t oldest = 0;
    for (size_t i = 1; i < nodes_.size(); i++)
        if (nodes_[i].lastMs < nodes_[oldest].lastMs) oldest = i;
    nodes_.erase(nodes_.begin() + oldest);
    return oldest;
}

size_t NodeTable::update(const Classified &c, uint32_t nowMs) {
    if (c.proto != LP_MESHTASTIC) return SIZE_MAX; // only Meshtastic carries an id in Phase 1
    uint32_t id = c.mt.from;

    for (size_t i = 0; i < nodes_.size(); i++) {
        LoraNode &n = nodes_[i];
        if (n.proto == LP_MESHTASTIC && n.id == id) {
            n.rssi = c.rssi;
            if (c.rssi > n.bestRssi) n.bestRssi = c.rssi;
            n.snr = c.snr;
            if (n.count < 0xFFFF) n.count++;
            n.lastMs = nowMs;
            n.hopLimit = c.mt.hopLimit();
            n.hopStart = c.mt.hopStart();
            n.flags |= flagsFromHeader(c.mt);
            // "Chatty" heuristic: many frames in a short window.
            if (n.count > 20 && (nowMs - n.firstMs) < 120000UL) n.flags |= NF_CHATTY;
            if (c.mtName[0]) strlcpy(n.name, c.mtName, sizeof(n.name));
            return i;
        }
    }

    if (nodes_.size() >= MAX_NODES) evictOldest();
    LoraNode n = {};
    n.proto = LP_MESHTASTIC;
    n.id = id;
    if (c.mtName[0]) strlcpy(n.name, c.mtName, sizeof(n.name));
    n.rssi = n.bestRssi = c.rssi;
    n.snr = c.snr;
    n.count = 1;
    n.hopLimit = c.mt.hopLimit();
    n.hopStart = c.mt.hopStart();
    n.flags = flagsFromHeader(c.mt);
    n.firstMs = n.lastMs = nowMs;
    nodes_.push_back(n);
    return nodes_.size() - 1;
}

} // namespace loramp

#endif
