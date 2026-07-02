# LoRa Recon

Passive, receive-only LoRa / LoRaWAN reconnaissance for the LilyGo T-Deck Plus (EU868), built
on top of Bruce's existing SX1262 radio bring-up. The device listens across the EU868 band,
decodes what's obtainable from a passive capture, and shows it on-screen in plain English.

**The radio never transmits.** No beacons, no probes, no replies, no join attempts. This is a
listen-only tool.

## How to open it

Main Menu → **LoRa** → **Recon**.

On open, a deterministic parser self-test runs first (synthetic test vectors, no radio
involved) and shows a green "parser self-test: OK" line — if that ever turns red, something in
the decoder has regressed.

## What it does

- Sweeps the 8 EU868 uplink channels (867.1–868.5 MHz) × spreading factors SF7–SF12, with
  per-SF dwell times from 2 s (SF7) to 20 s (SF12) — one full sweep takes ~400 s.
- Periodically parks on the RX2 downlink channel (869.525 MHz / SF12, inverted IQ).
- Decodes LoRaWAN MAC headers: message type, DevAddr, FCtrl flags (ADR / ADRACKReq / ACK /
  ClassB-FPending), FCnt, FOpts MAC commands (1.0.x plaintext — LinkCheck, LinkADR, DutyCycle,
  RXParamSetup, DevStatus, NewChannel, RXTimingSetup, TxParamSetup, DlChannel, DeviceTime),
  FPort, and Join Request fields (JoinEUI, DevEUI, DevNonce).
- Flags anomalies: a DevNonce repeated for the same DevEUI (possible replayed join), or an
  FCnt lower than previously seen for a DevAddr (possible reset/rejoin/replay).
- Shows RF context per frame: frequency, SF, bandwidth, RSSI, SNR, **link margin** (RSSI minus
  the SX1262's sensitivity floor for that SF) with a one-line strength assessment, length, and
  estimated airtime.

## What it never does

- **Never decodes FRMPayload.** Application payload is AES-encrypted; passive recon has no
  session key. Only its length is shown, never a "decoded" value.
- **Never validates the MIC.** The 4 MIC bytes are extracted and displayed, but their validity
  can't be checked without the device's network/session key. They're shown as read, not
  verified.
- **Never shows "distance."** Distance depends on the sender's TX power, path loss, and
  antenna gains — none of which are knowable from a passive capture. Link margin is shown
  instead.

## Screens

- **Sweep** (default view) — a scrollable table of all 48 channel×SF combos plus a dedicated
  RX2 row, each showing packet count, last RSSI, and last DevAddr seen. The row currently
  being scanned is marked `>` and shown in green.
- **Frame list** (`f`) — captured frames, newest first: age, short frame-type code, DevAddr or
  DevEUI, RSSI, and a `!` marker for anomalies.
- **Frame detail** (select a row in the frame list) — the full human-readable breakdown: RF
  metrics, frame type, addressing/flags, MAC commands, join fields, and any anomalies, grouped
  and word-wrapped for the small screen.

## Controls

| Screen | Up/Down | Select | Other | Back |
|---|---|---|---|---|
| Sweep | navigate rows | lock: fix SF, hop channels only (RX2 row: park on RX2 indefinitely) | `x` = exact-lock this one channel+SF, no hopping · `f` = frame list · `r` = reset stats | Backspace = exit to LoRa menu |
| Frame list | navigate frames | open detail view | | Backspace = back to sweep |
| Frame detail | scroll | | | Backspace = back to frame list |

**"Back" is the physical Backspace/Delete key (⌫)** on the T-Deck's keyboard — there is no
labeled Esc key on this device.

## The realities of a single radio

The SX1262 can only listen to **one frequency and one spreading factor at a time**. It cannot
capture the whole EU868 band simultaneously — that's why this tool sweeps in the time domain
rather than monitoring everything at once. A channel/SF combo showing zero packets over a
short window doesn't mean nothing is there; it may simply not have been listening at the right
moment. Locking onto a specific SF (or a specific channel+SF) trades broad coverage for a
better chance of catching a specific, known transmitter.

## Passive/receive-only and legal notes

- The radio only calls receive-side APIs (`begin`, `startReceive`, `readData`, `standby`,
  and the various `set*` configuration calls). It never calls a transmit API — verified by
  code review and confirmed via serial logging that no transmit ever occurs.
- Attach the antenna before powering the radio.
- This is intended for authorized, legal RF research on your own equipment or with permission.
  Passive reception generally carries no ETSI EN 300.220 transmit duty-cycle obligation (since
  nothing is transmitted), but monitoring/interception rules vary by jurisdiction — check your
  local regulations before use.

## Known limitations

- Live-capture behavior (real frames arriving during a sweep, anomaly detection against real
  replay/regression traffic) has been verified through code review and the deterministic
  parser self-test, but not yet confirmed against a live transmitter in this development
  session — no Meshtastic node or LoRaWAN device was available to test against. The UI, sweep
  timing, and lock modes have all been confirmed working on real hardware.
- The DevAddr "operator hint" and DevEUI "OUI hint" are both deliberately small and
  best-effort. Wrong or missing hints are expected — they're illustrative, not authoritative.
- FOpts MAC command decoding assumes LoRaWAN 1.0.x (plaintext FOpts). In 1.1, FOpts are
  encrypted and will show as an unrecognized CID rather than a decoded command — this is
  detected and surfaced, not silently misdecoded.
- SD logging (JSON/CSV) and a Meshtastic-mode listener (sync word `0x2B`) were considered as
  optional extras but not implemented in this pass.

## Code layout

- `src/core/menu_items/LoRaMenu.{h,cpp}` — adds the "Recon" entry to the existing LoRa submenu.
- `src/modules/lora/LoRaWANParser.{h,cpp}` — stateless LoRaWAN frame decoder + human-readable
  description generator + deterministic self-test (Appendix A vectors from the task brief).
- `src/modules/lora/LoRaRecon.{h,cpp}` — radio bring-up/retuning, the channel×SF sweep/lock
  state machine, anomaly tracking, captured-frame storage, and the three-screen UI.
- `boards/lilygo-t-deck/lilygo-t-deck.ini` — adds `-DLORA_BUSY=13`, the SX1262 BUSY pin, which
  was previously undefined for this board.
