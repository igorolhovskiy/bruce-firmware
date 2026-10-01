#ifndef __LORA_RECON_MULTI_H__
#define __LORA_RECON_MULTI_H__
#if !defined(LITE_VERSION)

// Multi-protocol passive LoRa recon (Phase 1: Meshtastic). Brings up the SX1262
// in the Meshtastic LongFast / EU868 config (receive-only), classifies each
// frame, and maintains a NODES table + a recent-FRAMES list. Never transmits;
// restores nothing to transmit. See bruce-lora-multiproto-TASK.md.
void loraReconMulti();

#endif
#endif // __LORA_RECON_MULTI_H__
