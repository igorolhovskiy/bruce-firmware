#ifndef __TRACKER_DETECTOR_H__
#define __TRACKER_DETECTOR_H__

// Passive (receive-only) detector for unwanted BLE location trackers: Apple
// Find My / AirTag, Tile, and Samsung SmartTag. Builds a live table (first seen,
// count, last seen, signal, separated-from-owner state), sortable by how long a
// tracker has been following you / how recently it was seen, and logs every raw
// sighting to SD for offline analysis. BLE menu -> "Tracker Detector".
void tracker_detector();

#endif
