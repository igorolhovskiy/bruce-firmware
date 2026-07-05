# WiFi Passive Recon

A **receive-only** 2.4 GHz recon tool for the T-Deck Plus (branch `wifi-passive-recon`). It never
transmits: it runs the radio in STA mode (an idle, unconnected STA sends nothing) with promiscuous
management-frame capture, so it observes without touching the air. WiFi menu → **Passive Recon**.

Three views (cycle with **SEL**), one shared promiscuous session and channel hopper:

## Probes — client / PNL logger
Every probe *request* seen: the device MAC and the SSID it is searching for (its Preferred Network
List), signal, and a hit count. Directed probes (named SSID) are white; broadcast probes are dimmed.
Useful for client presence/tracking recon. First-seen `(MAC, SSID)` pairs are logged to SD.

## Deauth — flood detector
Counts deauth/disassoc frames, computes a per-second **rate**, lists the top source MACs, and shows
the last reason code. When the rate crosses the threshold the header turns red with `** FLOOD **`.
Totals are counted in the capture callback itself, so the metric stays accurate even if the event
ring overflows during a heavy flood. This is a **defensive** tool — it detects someone attacking a
network, it does not attack. Every event is logged to SD.

## APs — encryption + 802.11w / PMF
Access points heard (from beacons / probe responses): channel, SSID, encryption
(OPEN/WEP/WPA/WPA2/WPA3, WPA3 detected via the SAE AKM suite), and **PMF** status parsed from the RSN
capabilities — `-` none, `cap` capable, `REQ` required. PMF-required APs (which are immune to the
deauth/handshake-capture tools) are highlighted in cyan, so this doubles as a "what can I actually
deauth" recon pass. First-seen BSSIDs are logged to SD.

## Controls
- **SEL** — cycle Probes → Deauth → APs
- **trackball up/down** — scroll the list
- **`l`** — lock / unlock channel hopping (hops channels 1–13 by default, ~300 ms each; lock to dwell)
- **Backspace / ⌫** — exit (restores the previous WiFi mode)

## SD logs (`/BruceRecon/`, best-effort)
- `probes.csv` — `uptime_ms,mac,ssid,rssi,channel` (first-seen per MAC+SSID)
- `deauth.csv` — `uptime_ms,channel,type,src,dst,bssid,reason` (every event)
- `aps.csv` — `uptime_ms,bssid,ssid,channel,enc,pmf,rssi` (first-seen per BSSID)

## Notes
- Purely passive: STA mode, no beacons, no probes, no injection — safe to run anywhere, no EU TX
  concerns. Legal to observe; acting on what you find is your responsibility.
- Implementation: `src/modules/wifi/passive_recon.{h,cpp}`, one line in `WifiMenu.cpp`. The rx
  callback only parses each frame into a compact event and pushes it to a single-producer ring; the
  main loop drains it, updates the models, draws (per-row diffed, no flicker), and writes SD.
