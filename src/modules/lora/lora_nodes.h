#ifndef __LORA_NODES_H__
#define __LORA_NODES_H__
#if !defined(LITE_VERSION)

#include "lora_classify.h"
#include <stdint.h>
#include <vector>

// ---------------------------------------------------------------------------
// LoRa NODES table: one row per transmitter, fed by classified frames. Keyed by
// (proto, id) - for Meshtastic the id is the header's `from` node number. Tracks
// the name it announced, signal, how often, and operator-relevant flags. No
// radio/display - unit-tested offline. Flag set + "one row per transmitter"
// model adapted from skizzophrenic/SquachWatch-CYD lora_nodes.h (GPL-3.0).
// ---------------------------------------------------------------------------

namespace loramp {

enum NodeFlags : uint8_t {
    NF_HOPS_HIGH = 0x01, // Meshtastic hop_start above the default of 3
    NF_MQTT = 0x02,      // relaying via MQTT (via_mqtt bit set)
    NF_OLD_FW = 0x04,    // hop_start == 0: pre-2.6 firmware heuristic
    NF_CHATTY = 0x08,    // seen more often than a quiet node (heuristic)
};

struct LoraNode {
    uint8_t proto;  // loramp::Proto
    uint32_t id;    // Meshtastic `from` node number
    char name[20];  // announced long-name ("" until a NODEINFO is heard)
    int8_t rssi;    // last
    int8_t bestRssi;
    float snr;
    uint16_t count; // frames heard from this node
    uint8_t flags;  // NodeFlags bitmask
    uint8_t hopLimit;
    uint8_t hopStart;
    uint32_t firstMs;
    uint32_t lastMs;
};

class NodeTable {
public:
    void clear() { nodes_.clear(); }
    size_t size() const { return nodes_.size(); }
    const LoraNode &at(size_t i) const { return nodes_[i]; }

    // Fold one classified frame into the table (create or update its row).
    // `nowMs` is millis(). Returns the affected row index, or SIZE_MAX if the
    // frame carries no usable transmitter id (e.g. non-Meshtastic for now).
    size_t update(const Classified &c, uint32_t nowMs);

private:
    static constexpr size_t MAX_NODES = 128;
    std::vector<LoraNode> nodes_;
    size_t evictOldest();
};

} // namespace loramp

#endif
#endif // __LORA_NODES_H__
