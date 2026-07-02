#ifndef __MESHTASTIC_LF_H__
#define __MESHTASTIC_LF_H__
#if !defined(LITE_VERSION)

// Minimal Meshtastic text client on the default LongFast channel (EU_868).
// Two-way: receives + decrypts + displays text, and composes + encrypts + sends
// text into the mesh. Leaf/client node only - no routing/rebroadcast/MQTT.
// Duty-cycle limited (EU868 10%). See docs/meshtastic-notes.md for the protocol
// constants (anchored to Meshtastic firmware v2.7.26).
void meshtasticChannel();

#endif
#endif
