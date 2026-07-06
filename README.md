![Bruce Main Menu](./media/pictures/bruce_banner.jpg)

# :shark: Bruce — T-Deck Plus fork

Bruce is a versatile ESP32 firmware that supports a ton of offensive features focusing on
facilitating Red Team operations.

**This is a personal fork focused ONLY on the [LilyGo T-Deck Plus](https://lilygo.cc/products/t-deck-plus-1)**
(ESP32-S3, 2.8" ST7789 320×240, trackball + QWERTY keyboard, WiFi + LoRa). It tracks upstream
[Bruce](https://github.com/pr3y/Bruce) and adds a handful of T-Deck-specific features and hardware
enablements. **All fork-specific extras are FULLY VIBECODED** — use at your own risk.

For everything about stock Bruce (other boards, the full feature set, the web flasher, the shop),
see the upstream project: <https://github.com/pr3y/Bruce> and the [wiki](https://wiki.bruce.computer/).

### From the original Bruce project

**Check their fully open-source hardware too:** https://bruce.computer/boards

**Also check the official Shop!! Buy here and support them:** https://bruce-devices.myshopify.com/

**Discord:** contact the Bruce community in their [Discord Server](https://discord.gg/WJ9XF9czVT)!

## :sparkles: What this fork adds

Features developed in this fork, on top of stock Bruce. Each is T-Deck Plus only unless noted.

- **[WiFi Analyzer](./docs/wifi-analyzer-README.md)** — passive 2.4 GHz signal-strength bar graph
  with async scanning and channel/AP highlighting (receive-only).
- **[WiFi Passive Recon](./docs/wifi-passive-recon-README.md)** — RX-only promiscuous management-frame capture (WiFi → Passive Recon);
  never transmits. Three SEL-cycled views over a shared channel hopper: client probe requests with
  the SSIDs (preferred-network list) they search for; a deauth/disassoc flood detector (count,
  per-second rate, top sources, red FLOOD alert); and an AP list showing encryption plus 802.11w/PMF
  parsed from RSN caps, with PMF-required (deauth-immune) APs highlighted. Logs to SD
  (`/BruceRecon/{probes,deauth,aps}.csv`) and restores the prior WiFi mode on exit.
- **WiFi CSA Attack** — Channel Switch Announcement attack (Wifi Atks → Target Atks → CSA Attack):
  injects spoofed beacons from the target BSSID carrying an 802.11h CSA element so associated clients
  hop to a bogus channel and drop off. Destination channel is adjustable live with the trackball.
  Because CSA rides in unprotected beacons, it works where deauth is blocked by PMF. Authorized
  testing only.
- **[LoRa Recon](./docs/lora-recon-README.md)** — passive, receive-only LoRa/LoRaWAN
  reconnaissance (EU868): channel/SF sweep, human-readable frame decode, replay/FCnt anomaly hints.
- **[Meshtastic LF](./docs/meshtastic-README.md)** — two-way Meshtastic text client on the default
  LongFast channel (EU868): receive/decrypt/display and compose/encrypt/send text, heard-nodes
  list, duty-cycle limited. Interoperates with stock Meshtastic (default key). Broadcasts a
  self-NodeInfo so peers list this device by name rather than a bare `!id`, stamps each conversation
  line with a wall-clock (or uptime-relative) time, transliterates Latin-1 accents to ASCII so EU
  mesh text is readable, and can dump a raw RX diagnostic log to SD (`/meshtastic_raw.log`).
- **IR via M5Stack Unit IR** — full Bruce IR (TV-B-Gone, receiver, custom IR) over the T-Deck Plus
  Grove port (GPIO43/44) using an external M5Stack Unit IR.
- **RFID2 extensions** — for the M5Stack RFID2 (PN532) on the Grove port: load a MIFARE key
  dictionary from SD, decode/display NDEF records, NTAG21x tools (signature, counter, password),
  a continuous UID logger (recon mode), and gen2/CUID magic-card clone with unbrick. The Grove I2C
  bus is routed to `Wire1` so the reader no longer conflicts with the keyboard on the shared bus.
- **[BLE Tracker Detector](./docs/ble-tracker-detector-README.md)** — passive, receive-only scan (BLE → Tracker Detector) that classifies
  advertisements as Apple Find My/AirTag, Tile, or Samsung SmartTag; builds a live per-device table
  of dwell time, hit count, last-seen age and RSSI (sort cycles with SEL); highlights persistent
  trackers (dwell ≥ 5 min) as potential followers; and logs every sighting to SD
  (`/BruceTrackers/trackers.csv`) for offline analysis.
- **BLE scan improvements** — resolves unnamed devices to a vendor from the BLE company ID (works
  even for randomized MACs) and a device type from GAP Appearance, so the list shows
  name → `[Vendor]` → address instead of bare addresses; the detail screen adds Vendor/Type lines and
  Backspace returns to the device list. The BLE spam vectors were also expanded (~125 real Fast Pair
  model IDs, plus more Apple Nearby-Action pairing-prompt types).
- **LED name badge BLE sender** — send text to 44×11 LSLED/VBLAB LED badges over BLE
  (BadgeMagic protocol), from the BLE menu.
- **Hardware enablement** — microphone via the ES7210 codec, speaker over I2S, and GPS clock sync.
- **Input tuning** — the trackball accumulates pulses and only advances one step past a
  configurable sensitivity threshold (with debounce), so light nudges no longer over-scroll, and
  the capacitive touchscreen can be turned off to stop accidental grip presses. Both live under
  **Config → System Config** (`Trackball Sens.` and `Touch`) and persist across reboots.

## :building_construction: Building & flashing

The T-Deck Plus target env is **`lilygo-t-deck-pro`** (despite the name — see the comment in
`boards/lilygo-t-deck/lilygo-t-deck.ini`).

```sh
pio run -e lilygo-t-deck-pro                 # compile
pio run -e lilygo-t-deck-pro -t upload       # compile + flash over USB (/dev/ttyACM0)
pio device monitor -b 115200                 # serial monitor
```

If upload fails: hold the trackball centre (BOOT), plug in USB, start the upload, press RST after.

## :computer: Stock Bruce features

These are inherited from upstream Bruce and available on the T-Deck Plus. See the
[wiki](https://wiki.bruce.computer/) for details on each.

<details>
  <summary><h2>WiFi</h2></summary>

- [x] Connect to WiFi
- [x] WiFi AP
- [x] Disconnect WiFi
- [x] [WiFi Atks](https://wiki.bruce.computer/features/wifi/#wifi-atks)
  - [x] [Beacon Spam](https://wiki.bruce.computer/features/wifi/#beacon-spam)
  - [x] [Target Atk](https://wiki.bruce.computer/features/wifi/#target-atks)
    - [x] Information
    - [x] Target Deauth
    - [x] EvilPortal + Deauth
  - [x] Deauth Flood (More than one target)
- [x] [Wardriving](https://wiki.bruce.computer/features/gps/#wardriving)
- [x] [TelNet](https://wiki.bruce.computer/features/wifi/#telnet)
- [x] [SSH](https://wiki.bruce.computer/features/wifi/#ssh)
- [x] [RAW Sniffer](https://wiki.bruce.computer/features/wifi/#raw-sniffer)
- [x] [TCP Client](https://wiki.bruce.computer/features/wifi/#client-tcp)
- [x] [TCP Listener](https://wiki.bruce.computer/features/wifi/#listen-tcp)
- [x] [Evil Portal](https://wiki.bruce.computer/features/wifi/#evil-portal)
- [x] [Scan Hosts](https://wiki.bruce.computer/features/wifi/#scan-hosts) (with TCP Port scanning)
- [x] [Responder](https://wiki.bruce.computer/features/wifi/#responder)
- [x] [Arp Spoofing](https://wiki.bruce.computer/features/wifi/#arp-spoofing)
- [x] [Arp Poisoning](https://wiki.bruce.computer/features/wifi/#arp-poisoning)
- [x] [Wireguard Tunneling](https://wiki.bruce.computer/features/wifi/#wireguard-tunneling)
- [x] Brucegotchi
  - [x] Pwnagotchi friend
  - [x] Pwngrid spam faces & names
    - [x] [Optional] DoScreen a very long name and face
    - [x] [Optional] Flood uniq peer identifiers

> This fork adds **WiFi Analyzer**, **WiFi Passive Recon**, and a **CSA Attack** (under Target Atks) —
> see "What this fork adds" above.
</details>

<details>
  <summary><h2>BLE</h2></summary>

- [x] [BLE Scan](https://wiki.bruce.computer/features/ble/#ble-scan)
- [x] Bad BLE - Run Ducky scripts, similar to [BadUsb](https://wiki.bruce.computer/features/ble/#badble)
- [x] BLE Keyboard
- [x] iOS Spam
- [x] Windows Spam
- [x] Samsung Spam
- [x] Android Spam
- [x] Spam All

> This fork adds a passive **Tracker Detector**, **BLE scan name resolution**, expanded spam vectors,
> and the **LED name badge sender** — see "What this fork adds" above.
</details>

<details>
  <summary><h2>RF</h2></summary>

- [x] Scan/Copy
- [x] [Custom SubGhz](https://wiki.bruce.computer/features/rf/#replay-payloads-like-flipper)
- [x] Spectrum
- [x] Jammer Full (sends a full squared wave into output)
- [x] Jammer Intermittent (sends PWM signal into output)
- [x] Config
  - [x] RF TX Pin
  - [x] RF RX Pin
  - [x] RF Module
    - [x] RF433 T/R M5Stack
    - [x] [CC1101 (Sub-Ghz)](https://wiki.bruce.computer/features/rf/#cc1101)
  - [x] RF Frequency
- [x] Replay
</details>

<details>
  <summary><h2>RFID</h2></summary>

- [x] Read tag
- [x] Read 125kHz
- [x] Clone tag
- [x] Write NDEF records
- [x] Amiibolink
- [x] Chameleon
- [x] Write data
- [x] Erase data
- [x] Save file
- [x] Load file
- [x] Config
  - [x] [RFID Module](https://wiki.bruce.computer/features/rfid/#supported-modules)
    - [x] PN532
    - [x] PN532Killer
- [ ] Emulate tag

> See **RFID2 extensions** under "What this fork adds" above for the fork's added
> M5Stack RFID2 features.
</details>

<details>
  <summary><h2>IR</h2></summary>

- [x] TV-B-Gone
- [x] IR Receiver
- [x] [Custom IR (NEC, NECext, SIRC, SIRC15, SIRC20, Samsung32, RC5, RC5X, RC6)](https://wiki.bruce.computer/features/ir/#replay-payloads-like-flipper)
- [x] Config - [X] Ir TX Pin - [X] Ir RX Pin

> On the T-Deck Plus, IR runs over an external M5Stack Unit IR on the Grove port — see
> "What this fork adds" above.
</details>

<details>
  <summary><h2>FM</h2></summary>

- [x] [Broadcast standard](https://wiki.bruce.computer/features/fm/#broadcast-standard)
- [x] [Broadcast reserved](https://wiki.bruce.computer/features/fm/#broadcast-standard)
- [x] [Broadcast stop](https://wiki.bruce.computer/features/fm/#broadcast-stop)
- [ ] [FM Spectrum](https://wiki.bruce.computer/features/fm/#fm-spectrum)
- [ ] [Hijack Traffic Announcements](https://wiki.bruce.computer/features/fm/#hijack-ta)
- [ ] [Config](https://wiki.bruce.computer/features/fm/#bookmark_tabs-config)
</details>

<details>
  <summary><h2>NRF24</h2></summary>

- [x] [NRF24 Jammer](https://wiki.bruce.computer/features/nrf24/)
- [x] 2.4G Spectrum
- [ ] Mousejack
</details>

<details>
  <summary><h2>LoRa</h2></summary>

- [x] Chat (Bruce-to-Bruce)
- [x] [LoRa Recon](./docs/lora-recon-README.md) — fork feature (see above)
- [x] [Meshtastic LF](./docs/meshtastic-README.md) — fork feature (see above)
</details>

<details>
  <summary><h2>Scripts</h2></summary>

- [x] [JavaScript Interpreter](https://wiki.bruce.computer/features/js-interpreter/) [Credits to justinknight93](https://github.com/justinknight93/Doolittle)
</details>

<details>
  <summary><h2>Others</h2></summary>

- [x] Mic Spectrum
- [x] [QRCodes](https://wiki.bruce.computer/features/others/#qrcodes)
  - [x] Custom
  - [x] PIX (Brazil bank transfer system)
- [x] [SD Card Mngr](https://github.com/pr3y/Bruce/wiki/Others#sd-card-mngr)
  - [x] View image (jpg)
  - [x] File Info
  - [x] [Wigle Upload](https://wiki.bruce.computer/features/gps/#how-to-use-wigle)
  - [x] Play Audio
  - [x] View File
- [x] LittleFS Mngr
- [x] [WebUI](https://wiki.bruce.computer/controlling-device/webui/)
  - [x] Server Structure
  - [x] Html
  - [x] SDCard Mngr
  - [x] Spiffs Mngr
- [x] Megalodon
- [x] [BADUsb (New features, LittleFS and SDCard)](https://wiki.bruce.computer/features/others/#badusb)
- [x] USB Keyboard
- [x] [iButton](https://wiki.bruce.computer/features/others/#ibutton)
- [x] LED Control
</details>

<details>
  <summary><h2>Clock</h2></summary>

- [x] RTC Support
- [x] NTP time adjust
- [x] Manual adjust
</details>

<details>
  <summary><h2>Connect (ESPNOW)</h2></summary>

- [x] Send File
- [x] Receive File
- [x] Send Commands
- [x] Receive Commands
</details>

<details>
  <summary><h2>Config</h2></summary>

- [x] Brightness
- [x] Dim Time
- [x] Orientation
- [x] UI Color
- [x] Boot Sound on/off
- [x] Clock
- [x] Sleep
- [x] Restart
</details>

## :clap: Acknowledgements

This fork stands entirely on upstream [Bruce](https://github.com/pr3y/Bruce) and its contributors.
Thanks to [@pr3y](https://github.com/pr3y), [@bmorcelli](https://github.com/bmorcelli),
[@IncursioHack](https://github.com/IncursioHack), [@rennancockles](https://github.com/rennancockles),
[@7h30th3r0n3](https://github.com/7h30th3r0n3), [@eadmaster](https://github.com/eadmaster),
[@Tawank](https://github.com/Tawank), and everyone who contributed to the project. :heart:

## :construction: Disclaimer

Bruce is a tool for cyber offensive and red team operations, distributed under the terms of the Affero General Public License (AGPL). It is intended for legal and authorized security testing purposes only. Use of this software for any malicious or unauthorized activities is strictly prohibited. By downloading, installing, or using Bruce, you agree to comply with all applicable laws and regulations. This software is provided free of charge, and we do not accept payments for copies or modifications. The developers of Bruce assume no liability for any misuse of the software. Use at your own risk.
