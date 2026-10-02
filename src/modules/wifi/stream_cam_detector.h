#ifndef __STREAM_CAM_DETECTOR_H__
#define __STREAM_CAM_DETECTOR_H__

// Traffic-pattern (streaming) hidden-camera detector. Passive, receive-only.
// Dwells per WiFi channel and tallies per-station 802.11 data-frame stats, then
// flags stations whose traffic looks like a video stream (sustained + mostly
// large frames + upstream) - catching unknown-vendor cameras the OUI/SSID
// detector misses. No payload decryption. Confidence LOW/MED only (Phase 1);
// a motion-correlation step (Phase 2) is what confirms "pointed at you".
// See bruce-stream-camera-TASK.md.
void stream_cam_detector();

#endif // __STREAM_CAM_DETECTOR_H__
