#ifndef __CS_GPS_H__
#define __CS_GPS_H__

#include <stdint.h>

// ---------------------------------------------------------------------------
// Counter-Surveil GPS: a non-blocking position source shared by the Detector
// tools that care whether a device MOVES WITH YOU (Ambient Watch, Tracker
// Detector, Follower Scan). Owns the GPS UART while a tool runs (begin/end),
// is drained from the tool's main loop (poll), and keeps a tiny per-device
// movement track. Receive-only on the radios; the only thing ever sent is UBX
// configuration to the on-board GPS receiver.
//
// Mode (session-wide, toggled with 'p' in the tools):
//   ON  - default. Continuous 1 Hz tracking; on a u-blox the NMEA output is
//         trimmed to RMC+GGA. Receiver power-save is deliberately not used:
//         indoors it lost the fix for minutes (see applyMode() in cs_gps.cpp).
//   OFF - UART closed, behaviour as before GPS support.
//
// "Moved with you" follows AirGuard (Heinrich et al. 2022): sightings at >= 3
// distinct places (FOLLOW_PLACES, >= PLACE_STEP_M apart) spanning >= 400 m
// (FOLLOW_DIST_M). Tools combine it with their time rule, so a car beside you
// at a traffic light for 2 km does not count on distance alone.
// ---------------------------------------------------------------------------

namespace csgps {

enum Mode : uint8_t { MODE_OFF = 0, MODE_ON = 1 };

constexpr uint16_t PLACE_STEP_M = 100;
constexpr uint16_t FOLLOW_DIST_M = 400;
constexpr uint8_t FOLLOW_PLACES = 3;

struct Fix {
    float lat, lon;
    uint8_t sats;
};

// Per-device movement summary (20 bytes). Zero-init = "never seen with a fix".
struct Track {
    float lat0, lon0;     // first position this device was seen at
    float anchLat, anchLon; // last counted "place"
    uint16_t maxDistM;    // farthest from (lat0, lon0) it was seen at
    uint8_t places;       // distinct places (>= PLACE_STEP_M apart) seen at
    uint8_t has;          // 1 once lat0/lon0 are set
};

Mode mode();
const char *modeName();
void cycleMode(); // toggle on/off (opens/closes the UART)

void begin(const char *tag); // open UART + identify module; tag prefixes serial logs
void end();                  // restore receiver to full power + default NMEA, close UART
void poll();                 // drain UART; call every main-loop pass

bool fix(Fix &out);       // true if a fresh, good-quality fix is available
const char *statusStr();  // short header text, e.g. "gps:7sat"

float distM(float lat1, float lon1, float lat2, float lon2);
void trackUpdate(Track &t, const Fix &f);
inline bool movedWithYou(const Track &t) {
    return t.has && t.maxDistM >= FOLLOW_DIST_M && t.places >= FOLLOW_PLACES;
}

bool selfTest(); // offline check of distance + track logic (serial-mirrored)

} // namespace csgps

#endif // __CS_GPS_H__
