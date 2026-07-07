#ifndef __WIFI_CAMERA_DETECTOR_H__
#define __WIFI_CAMERA_DETECTOR_H__

// Passive (receive-only) WiFi camera detector. Promiscuous management-frame
// capture; flags devices whose MAC OUI (or SSID pattern) matches a known IP/
// wireless-camera vendor. De-duplicated, RSSI-sorted table; low-confidence flag
// for generic Wi-Fi module OUIs. Counter-Surveil app. (Phase 1)
void wifi_camera_detector();

#endif
