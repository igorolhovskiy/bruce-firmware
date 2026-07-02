# Meshtastic LF — LongFast text client for Bruce (LilyGo T-Deck Plus)

A minimal, **two-way** Meshtastic text client for the Bruce firmware. It joins the default
**LongFast** channel of the EU868 Meshtastic mesh and lets the T-Deck **receive, decrypt, and
display** text messages and **compose, encrypt, and transmit** them — interoperating with stock
Meshtastic nodes/apps using the well-known default channel key.

> **This feature transmits.** It is duty-cycle limited and intended for a leaf/client node only.
> See **Legal & safety** below before use.

## What it does

- Joins **LongFast** on **EU_868** (≈**869.525 MHz**, SF11 / BW250 / CR4:5, sync `0x2b`, preamble 16,
  CRC on).
- **Receives** frames, filters by the LongFast channel-hash, **decrypts** (AES-128-CTR, default key),
  and decodes the `Data` protobuf. Text messages are shown; other port-numbers are identified by
  number.
- **Sends** text you compose on the QWERTY keyboard: builds a `Data` protobuf, encrypts it, frames it
  with a correct 16-byte `PacketHeader` (broadcast destination, our node-ID, hop-limit 3), and
  transmits — subject to a **mandatory EU868 10 % duty-cycle limiter**.
- Shows a **conversation** view, a **compose** action, and a **nodes-heard** view with names decoded
  from NODEINFO packets. Optional **SD logging** of the conversation to CSV.

## Opening it

Bruce menu → **LoRa** → **Meshtastic**. (Gated out of `LITE_VERSION` builds.)

On open it runs a deterministic **self-test** (protobuf / PSK / channel-hash / AES-CTR KATs / header /
TX-loopback / duty-cycle / NODEINFO-name) and shows OK/FAIL, then brings up the radio.

## Screens & controls

Back/exit is the physical **Backspace/Delete (⌫)** key.

- **Conversation (A):** scrolling messages, newest at the bottom. Own messages show `>>` in the accent
  colour; others show `name` (or `!nodeid`) `: text` with an `RSSI/SNR` tag. Chrome shows node-ID,
  `LongFast 869.5`, the **duty-cycle % used**, TX count, and RX/TX/BLK state.
  - **SEL (trackball centre)** or **`c`** → compose
  - **`n`** → nodes view
  - trackball **up/down** → scroll
  - **⌫** → exit the feature
- **Compose (B):** the standard Bruce keyboard ("Type message:"). Confirm to encrypt + send (blocked
  with a retry hint if the duty-cycle budget is exhausted); empty/cancel returns without sending.
- **Nodes (C):** node-ID (`!xxxxxxxx`), decoded name if heard, last RSSI/SNR, packet count, age.
  **`n`** or **⌫** returns to the conversation.

## Defaults

| Setting | Value |
|---|---|
| Region | EU_868 (869.4–869.65 MHz, 10 % duty, 27 dBm region cap) |
| Frequency | 869.525 MHz (LongFast slot 0) |
| Modem preset | LongFast — SF11 / BW250 kHz / CR4:5 |
| Sync word / preamble / CRC | `0x2b` / 16 / on |
| Channel | "LongFast", channel-hash `0x08` |
| Key | default PSK index 1 (`d4 f1 bb 3a … 4e 69 01`, AES-128) |
| Our node-ID | derived from the ESP32 MAC (`!%08x`), stable across boots |
| TX power | capped at +22 dBm (SX1262 max) |
| Hop limit | 3 |

All protocol constants were read from Meshtastic firmware **v2.7.26.54e0d8d** and are documented, with
source references, in `docs/meshtastic-notes.md`.

## Interop with a real node / phone app

Set the peer to **EU_868**, primary channel **LongFast** with the **default key**, modem preset
**LongFast**. Then: send from the app → it appears in the conversation; compose on the T-Deck → it
appears in the app. Sender node-IDs and RF metrics are shown.

## Autonomous / serial control

Every on-screen value is also mirrored to the USB serial log (115200). While the module is open,
**typing a line on serial transmits it as a text message** — handy for scripted testing. Received and
sent text, node-name decodes, and TX airtime/duty accounting are all logged.

## SD logging

If a microSD card is present, the conversation is appended to **`/meshtastic_log.csv`**:
`uptime_ms,dir,nodeid,name,rssi,snr,"text"` (`dir` = `rx`/`tx`). Best-effort; silently disabled with
no card.

## Legal & safety

- **Antenna before power — especially for TX.** Transmitting into a missing/mismatched antenna can
  destroy the SX1262 PA. Use an **EU868-band** antenna.
- **Duty cycle is enforced.** The EU868 869.4–869.65 MHz band allows **10 %** duty; the limiter tracks
  rolling airtime and blocks/delays TX that would exceed the budget (shown as "duty: N %" / "TX
  blocked"). Airtime/monitoring rules vary by country — **operate within your local regulations** and
  only on channels/regions you are permitted to use.
- **Leaf/client only.** No rebroadcast/routing on behalf of other nodes, no MQTT uplink, no
  admin/remote-hardware.
- **Privacy.** Default-key traffic is readable by anyone with the default key; the client only shows/
  logs what the on-device UI needs.

## Scope & limitations

**In scope:** one channel (LongFast default), receive+decrypt+display text, compose+encrypt+send text,
heard-nodes list with names, SD logging.

**Out of scope:** MQTT, position/telemetry/waypoint apps, PKI/admin/remote-hardware,
store-and-forward, multi-hop routing/rebroadcast, selectable modem preset, the full `MeshPacket`
surface.

**Known gap:** live bidirectional interop with a real Meshtastic node was **not verified on hardware**
in the development session (no peer available). RX was validated against real ambient LongFast traffic
(NODEINFO/POSITION decoded, names extracted); the TX frame was validated to be byte-correct and
stock-node-decodable offline. A live peer is needed to fully close this.

## Files

- `src/modules/lora/Meshtastic.{h,cpp}` — radio bring-up, RX/TX, UI, serial control, SD logging.
- `src/modules/lora/MeshtasticCodec.{h,cpp}` — header, PSK, channel-hash, AES-CTR, `Data`/`User`
  protobuf, duty-cycle tracker, self-test (pure/offline).
- `src/core/menu_items/LoRaMenu.cpp` — the "Meshtastic" submenu entry.

## Attribution / licensing

New code is AGPL-compatible (matching Bruce). Meshtastic-derived constants (default PSK, channel-hash
algorithm, nonce layout, wire tags, region/preset tables) were **re-derived** from the Meshtastic
firmware (GPL-3.0) and protobufs (Apache-2.0) rather than copied, and are attributed here and in
`docs/meshtastic-notes.md`.
