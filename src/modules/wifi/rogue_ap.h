#ifndef __ROGUE_AP_H__
#define __ROGUE_AP_H__

// Passive rogue-AP / Karma detector on the promiscuous capture core. Flags MITM /
// surveillance-rig signatures: one BSSID answering many distinct probed SSIDs
// (Karma), duplicate-SSID-different-BSSID (evil twin), and deauth floods.
// Receive-only. Counter-Surveil app. (Phase 3)
void rogue_ap();

#endif
