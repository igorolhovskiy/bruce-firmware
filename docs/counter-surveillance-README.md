# Counter-Surveil ("Detector") app

A top-level Bruce app (eye icon on the main menu, label **Detector**) that groups a family of
**passive, receive-only** detectors for surveillance-capable radio devices. Nothing here transmits:
no AP, no beacon, no probe/deauth/assoc TX, no BLE scan-requests (passive scan only), no injection.
Every detector restores the prior WiFi/BLE radio mode on exit.

Opening the app shows the **Counter-Surveil** submenu. All screens mirror their data to USB serial
(115200) and log raw sightings to the SD card under `/BruceDetector/`. Drawing uses per-row diffing,
so there is no periodic full-screen repaint / flicker.

Target board: **`lilygo-t-deck-pro`** (LilyGo T-Deck Plus). This is the only supported/verified build
target for this feature.

## Detectors

| Entry | What it flags | Signal / confidence | Transport | SD log |
|-------|---------------|---------------------|-----------|--------|
| **Tracker Detector** | Apple Find My / AirTag, Samsung SmartTag, Tile | known BLE tracker signatures; persistence + "separated from owner" | BLE passive | `trackers.csv` |
| **WiFi Camera** | IP/wireless cameras by MAC OUI or camera-name SSID | HIGH = camera-vendor OUI; MED = camera-ish SSID, unknown vendor; LOW = generic ESP/Realtek module + camera-ish name | WiFi promiscuous (ch 1–13) | `wifi_cams.csv` |
| **Drone Remote ID** | Drones broadcasting Open Drone ID (ASTM F3411), incl. operator location | decoded fields (Basic ID / Location / System); an operator location present is highlighted | WiFi vendor-IE/NAN **or** BLE service-data (toggle `m`) | `drones.csv` |
| **Rogue AP / Karma** | MITM / surveillance rigs | `K` Karma (one BSSID → ≥4 distinct SSIDs), `E` evil twin (same SSID, different BSSIDs), `D` deauth flood | WiFi promiscuous | `rogue_ap.csv` |
| **BLE Spy Tags** | Hidden BLE cameras / doorbells / recorders / vendor-flagged gadgets | HIGH = camera-vendor OUI on a public address; MED = device-name pattern or gadget company-ID; class column shown | BLE passive | `ble_spy.csv` |
| **Follower Scan** | An address persistently in range / seen across a move ("something is tailing you") | follower score from dwell time + count + signal + a big bonus for crossing a marked move (press **SEL** = "I moved") | WiFi probes **or** BLE (toggle `m`) | `followers.csv` |

### Shared vendor database

`src/modules/wifi/oui_db.{h,cpp}` — a compact, curated OUI→vendor table (camera / drone / IoT vendors,
plus generic ESP/Realtek module prefixes flagged low-confidence). It is a **seed**, not the full IEEE
registry; extend it in-code (or, later, from SD). Shared by the WiFi Camera, BLE Spy and Follower
detectors.

## Common controls

- `^` / `v` — scroll (and, where present, move the selection cursor).
- `SEL` — context action: cycle sort (Camera), open detail (Drone), mark "I moved" (Follower).
- `l` — lock the current channel (WiFi detectors).
- `m` — toggle transport WiFi↔BLE (Drone, Follower).
- `<-` (ESC) — exit; the radio mode is restored.
- Type any line in the serial monitor — dumps the current table (Camera, Rogue AP) or feeds a
  synthetic ODID hex message for headless parser validation (Drone).

## Confidence model

Hits are **heuristic**, not proof. Each detector shows an H/M/L confidence or a reason code so you can
judge. Generic Wi-Fi module OUIs (ESP/Realtek) and randomized addresses are down-weighted rather than
claimed as positive identifications. Verify a flagged device physically before acting on it.

## Explicit non-goals (hardware limits, not TODOs)

The board is an ESP32-S3 (2.4 GHz WiFi + BLE) with an SX1262 (narrow sub-GHz ISM LoRa only). It
therefore **cannot** detect:

- **Cellular** GPS trackers or IMSI-catchers — no cellular modem.
- **Analog RF bugs / non-ISM wireless mics** — no broadband SDR; the SX1262 only tunes narrow ISM.
- **Optical / lens-glint hidden cameras** — no optical sensor.
- **Zigbee / Thread (802.15.4)** devices — the ESP32-S3 lacks that radio.

These limits are also stated on-device under **Counter-Surveil → About / Limits**.

### Follower Scan caveat

Modern phones randomize their MAC / BLE address and will evade dwell tracking. Follower Scan is
effective against **fixed-address** gadgets and trackers not separated from their owner; randomized
addresses are marked `r` and down-weighted.

## Files

- App: `src/core/menu_items/CounterSurveilMenu.{h,cpp}` (+ registration in `src/core/main_menu.{h,cpp}`).
- Shared DB: `src/modules/wifi/oui_db.{h,cpp}`.
- WiFi detectors: `src/modules/wifi/{wifi_camera_detector,drone_remoteid,rogue_ap,follower_scan}.{h,cpp}`.
- BLE detector: `src/modules/ble/ble_spy_detector.{h,cpp}`.
- The existing `src/modules/ble/tracker_detector.{h,cpp}` was **relocated** here (removed from the BLE
  menu) unchanged.

## Build / flash / verify

```sh
pio run -e lilygo-t-deck-pro                 # compile
pio run -e lilygo-t-deck-pro -t upload       # flash over USB
pio device monitor -b 115200                 # serial monitor
```

To verify a detector headlessly, start the serial capture **first**, then navigate into the detector
(opening the port resets the device), wait for the `[...] starting` banner, and watch the mirrored
rows / `HIT` lines. Live-emitter checks (a real camera, a Remote-ID drone, a second device running
Karma/evil-twin, a known BLE gadget, a stationary tag) need the user and the screen.
