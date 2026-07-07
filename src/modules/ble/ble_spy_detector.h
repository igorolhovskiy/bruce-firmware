#ifndef __BLE_SPY_DETECTOR_H__
#define __BLE_SPY_DETECTOR_H__

// Passive BLE spy-gadget detector - extends the tracker-detector signature set to
// hidden BLE cameras / doorbells, audio-recorder gadgets, and generic BLE devices
// whose company-ID / OUI hits the shared vendor DB. Receive-only passive scan.
// Counter-Surveil app. (Phase 4)
void ble_spy_detector();

#endif
