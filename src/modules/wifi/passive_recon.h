#ifndef __PASSIVE_RECON_H__
#define __PASSIVE_RECON_H__

// Passive (receive-only) 2.4 GHz WiFi recon. Promiscuous management-frame capture
// with three views, none of which transmit:
//   - Probes:  client probe requests + the SSIDs (PNL) they search for.
//   - Deauth:  deauth/disassoc flood detector (counts, rate, top sources, alert).
//   - APs:     access points with encryption and 802.11w / PMF status.
// Channel-hops by default; press 'l' to lock the current channel. Logs to SD.
void passive_recon();

#endif
