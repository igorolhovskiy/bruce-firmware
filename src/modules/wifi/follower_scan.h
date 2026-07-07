#ifndef __FOLLOWER_SCAN_H__
#define __FOLLOWER_SCAN_H__

// Passive follower / tail detector. Unifies WiFi-probe MACs and BLE addresses into
// a dwell-time model (first-seen, last-seen, total in-range time, RSSI trend, and
// a "seen across a move" flag the user marks) and surfaces the address most likely
// tailing the user. Notes the MAC-randomization caveat in-UI. Counter-Surveil
// app. (Phase 5)
void follower_scan();

#endif
