# BLE Unwanted-Tracker Detector

A **receive-only** detector for BLE location trackers following you — Apple Find My / AirTag, Tile,
and Samsung SmartTag. **BLE menu → Tracker Detector.** It runs a continuous *passive* scan (it never
sends scan requests, so it's fully non-transmitting) and builds a live, sortable table, logging every
raw sighting to SD for later analysis.

## The table
Each detected tracker is one row: **type**, MAC tail, **dwell time** (how long between first and last
sighting — i.e. how long it's been near you), **hit count**, **last-seen** age, and **RSSI**. Apple
Find My devices broadcasting the long "separated from owner" frame get a `!` (those are the ones that
matter for stalking). The header shows the total and a **following:N** count of trackers that have
persisted past the 5-minute threshold — the "is something following me?" signal.

Colours: **red** = persistent (dwell ≥ 5 min, potential follower), **yellow** = Apple separated-from-
owner, white = normal.

## Sorting (button)
Press **SEL** to cycle the sort order:
1. **seen-time** — longest dwell first (default; the primary "following me longest" view)
2. **last-seen** — most recently spotted first
3. **count** — most sightings first

## Controls
- **SEL** — cycle sort mode
- **trackball up/down** — scroll
- **Backspace / ⌫** — exit (stops the scan, restores BLE state)

## SD log (`/BruceTrackers/trackers.csv`)
Every sighting is appended raw for offline analysis:
`uptime_ms, clock, type, mac, rssi, separated, raw_adv_hex`
(clock is wall-time `HH:MM:SS` once set, else `+uptime`). The raw advertising hex lets you re-derive
everything later and correlate across MAC rotations.

## What it detects
- **Apple Find My / AirTag** — manufacturer data (company `0x004C`) subtype `0x12`; the long frame
  (len ≥ `0x19`) flags "separated from owner".
- **Tile** — service (data/UUID) `0xFEED` / `0xFEEC`.
- **Samsung SmartTag** — service data `0xFD5A`.

## Honest limitations & future work
- **MAC rotation:** AirTags rotate their BLE address (and payload key) ~every 15 minutes while
  separated, so one physical tag can show as several rows over time. The timestamped raw log is what
  lets you correlate offline; a real follower still stands out by cumulative presence and RSSI.
- **GPS correlation** (not yet): the strongest "did it follow me across locations" signal is pairing
  each sighting with GPS. The T-Deck has GPS, but there's no shared location global today; wiring the
  GPS serial into the log is the natural next step.
- **Ring the tracker** (not yet): AirGuard-style, connect to a found AirTag and trigger its speaker to
  locate it physically. That's an *active* GATT action, deliberately left out of this passive tool.

Implementation: `src/modules/ble/tracker_detector.{h,cpp}` + one line in `BleMenu.cpp`. The NimBLE scan
callback only classifies + pushes a compact sighting to a single-producer ring; the main loop drains
it, updates the table, writes SD, and draws (per-row diffed, no flicker).
