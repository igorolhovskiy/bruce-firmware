# WiFi Analyzer — signal-strength visualiser for Bruce (LilyGo T-Deck)

A live **2.4 GHz WiFi analyzer** for the Bruce firmware. It scans nearby access points and draws each
one as a coloured **signal-strength bar** positioned on its WiFi channel — a dBm-vs-channel chart in
the style of the "Wifi Analyzer" phone apps.

> **Passive / receive-only.** It only performs standard WiFi scans. It never starts an AP, associates,
> deauthenticates, or transmits anything beyond what a normal scan does.

## What it does

- Runs repeated **asynchronous** WiFi scans (`WiFi.scanNetworks(async)`) so the UI stays responsive.
- For every AP found, plots a vertical **bar** at its channel; the bar's height encodes its **RSSI**
  against a fixed −30…−100 dBm scale. APs sharing a channel are drawn **side by side**.
- Each bar is outlined and labelled with its **SSID**, in a **stable colour** derived from the AP's
  BSSID (the same network keeps the same colour across rescans).
- The whole frame is rendered into an off-screen sprite and pushed in a single blit, so refreshes are
  **flicker-free**.
- Every scan is **mirrored to USB serial** (index, channel, RSSI, encryption, SSID).

Note: the ESP32 radio is **2.4 GHz only** — there is no 5 GHz band to display (unlike the phone apps'
2.4G/5G toggle). Channels **1–14** are shown on the x-axis.

## Opening it

Bruce menu → **WiFi** → **WiFi Analyzer**.

## Screen & controls

- **Graph:** dBm gridlines and labels (−40…−90) down the left, channels **1–14** along the bottom,
  and one coloured bar per AP with its SSID above it. The header shows the **AP count** and
  **scan / PAUSED** state.
- **Trackball left / right** → move the **highlight** between networks. The highlighted bar gets a
  brighter fill and a double outline, and its details appear on the bottom line:
  `SSID  chN  −NN dBm  <encryption>`.
- **Trackball centre (SEL)** → **pause / resume** the auto-rescan (useful to freeze a reading).
- **ESC** → exit (restores the previous WiFi mode).

## Defaults

| Setting | Value |
|---|---|
| Band / channels | 2.4 GHz, channels 1–14 |
| dBm scale (y-axis) | −30 dBm (top) … −100 dBm (bottom) |
| Rescan interval | ~2.5 s between scans (when not paused) |
| Hidden networks | follows the global **WiFi → Config → Hidden Networks** toggle |
| Bar colour | stable per-BSSID hash into a 10-colour palette |

## Autonomous / serial

Every scan is logged to the USB serial console (115200):

```
[WiFiAnalyzer] scan: 12 networks
   0  ch9    -50 dBm  WPA2/3  SFR_F4D2
   1  ch1    -63 dBm  WPA2    Livebox-122F
   ...
```

Pause/resume and open/close events are logged too. Because opening the USB serial port resets the
T-Deck to the main menu, capture like this: **start the serial monitor first, then navigate into
WiFi → WiFi Analyzer** and let a few scans stream.

## Scope & limitations

**In scope:** live 2.4 GHz AP scan, per-channel signal-strength bars, per-network colour + SSID label,
highlight + detail readout, pause/resume, serial mirroring.

**Out of scope / limitations:**
- 2.4 GHz only (no 5 GHz — hardware limitation).
- RSSI is a **momentary** reading from the last scan; a full scan takes a couple of seconds, so bars
  update at that cadence, not continuously.
- With many APs on one channel the side-by-side bars get narrow and SSID labels can crowd; the detail
  footer always shows the highlighted one clearly.
- Signal strength is **not distance** — it depends on the AP's TX power, antennas and path loss.

## Files

- `src/modules/wifi/wifi_analyzer.{h,cpp}` — scan loop, data model, bar rendering, input, serial mirror.
- `src/core/menu_items/WifiMenu.cpp` — the "WiFi Analyzer" menu entry (one line).

## Licensing

New code is AGPL-compatible, matching Bruce. It uses only Bruce's existing display/input abstractions
and the Arduino-ESP32 `WiFi` scan API.
