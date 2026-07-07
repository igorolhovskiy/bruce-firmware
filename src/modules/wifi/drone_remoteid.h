#ifndef __DRONE_REMOTEID_H__
#define __DRONE_REMOTEID_H__

// Passive Open Drone ID (Remote ID) detector. Parses ASTM F3411 broadcasts over
// WiFi (NAN action frames + beacon vendor-IE, OUI FA-0B-BC) and BLE service data:
// Basic ID, Location/Vector (drone lat/lon/alt/speed) and System (operator
// location). Lists nearby drones + operator position. Counter-Surveil app. (Phase 2)
void drone_remoteid();

#endif
