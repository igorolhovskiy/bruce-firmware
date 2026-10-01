#ifndef __AMBIENT_WATCH_H__
#define __AMBIENT_WATCH_H__

// Ambient Watch: one continuous PASSIVE scan that time-slices the radio between
// BLE and WiFi phases and collects threats (cameras / Flock / ALPR / Ring /
// trackers / spy gadgets / Flipper / Meta glasses / Pineapple / Pwnagotchi /
// drones) into a single de-duplicated, confidence-graded list. Receive-only;
// restores WiFi mode on exit. See bruce-ambient-watch-TASK.md.
void ambient_watch();

#endif // __AMBIENT_WATCH_H__
