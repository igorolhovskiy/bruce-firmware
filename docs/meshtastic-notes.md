# Meshtastic LongRange — investigation notes

Working notes for the "Meshtastic LF" feature (see `bruce-meshtastic-longrange-TASK.md` in the
parent folder). Kept here so intermediate findings survive across sessions; will be folded into
`docs/meshtastic-README.md` at Phase 9.

> **This feature TRANSMITS.** Unlike LoRa Recon (receive-only), this is a two-way mesh text
> client. The hard rules are duty-cycle compliance (EU868 10%), legal operation, antenna-before-power,
> and never fabricating protocol data.

## Toolchain / environment (reused from recon)

- PlatformIO runs from `.pyproject-pio/` (Python 3.12 via `uv`; system 3.14 is too new for
  `espressif32`). Activate before any `pio`: from `bruce-firmware/`, `source ../.pyproject-pio/bin/activate`.
- Target env: **`lilygo-t-deck-pro`** (T-Deck Plus). Sibling `lilygo-t-deck` is the non-Plus board.
- Serial: `/dev/ttyACM0` (confirmed present), 115200 baud.
- Reference tooling: `meshtastic` Python lib 2.7.9 in `.pyproject` (talks to a node over API — does
  NOT implement the on-air PHY crypto itself, so it is not directly a crypto-KAT generator).
  `openssl` present and used to generate the AES-CTR KATs below.

## Base branch decision — DECIDED

- **Base = `lora-recon`** (user chose to stack both features so one build has Recon + Meshtastic).
- Feature branch: **`meshtastic-longrange`**, branched from `lora-recon`.
- **Antenna:** user confirmed EU868 antenna attached — safe to power radio and transmit.
- **Interop peer:** none available right now — build + self-test + loopback verifiable this session;
  live bidirectional interop (Phase 7) flagged as an unverified gap until a real node is on hand.

## Bruce internals to reuse (confirmed against source)

- **Menu extension point:** `LoRaMenu::optionsMenu()` (`src/core/menu_items/LoRaMenu.cpp:8`) — add a
  `"Meshtastic"` entry to the `options` vector calling a new `meshtasticChannel()`. Same low-friction
  pattern as recon's `"Recon"` entry; no new `MenuItemInterface`, no main-menu registration change.
  Whole module gated `#if !defined(LITE_VERSION)`.
- **Radio pin/SPI helpers:** `LoRaRF.h` exposes `getLoraIrqPin()/getLoraBusyPin()/getLoraResetPin()/
  getLoraCsPin()/selectLoraSPIBus()`. `LORA_BUSY=13` already added to the board ini by recon. Our
  module owns its own independent `SX1262`/`Module` instance built from these helpers (same as
  `LoRaRecon.cpp`). RadioLib is `jgromes/RadioLib @ ^7.4.0`.
- **RX pattern (recon):** ISR sets a `volatile bool` flag (`onReconPacket`), main loop polls it,
  `readData()` + `getRSSI/getSNR/getTimeOnAir`, then `startReceive()` to re-arm. Guard with a
  `reconIrqEnabled` flag while reading. We mirror this and ADD a TX path (time-shared on one radio).
- **TX pattern (chat):** `LoRaRF.cpp:sendLoraMessage()` — disable IRQ, `radio->transmit(buf,len)`,
  `startReceive()` to re-arm, re-enable IRQ. Blocking transmit is fine for our small payloads.
- **Crypto:** `mbedtls/aes.h` already in-tree. Use `mbedtls_aes_crypt_ctr` for AES-128-CTR (see the
  counter-compatibility note below — mbedtls matches Meshtastic for our packet sizes).
- **Text input:** `keyboard(String, maxSize, msg, mask)` (`src/core/mykeyboard.h:5`). Returns `"\x1B"`
  on cancel (see chat's `if (msg == "\x1B") return;`).
- **Display:** `tft` global; `loopOptions()` for menus; `ScrollableTextArea`
  (`src/core/scrollableTextArea.h`) for the message log. Input via `check(SelPress/EscPress/NextPress/
  PrevPress/AnyKeyPress)`. **Back/exit key = physical Backspace/Delete (⌫) → `EscPress`** (recon Phase 2).
- Letter shortcuts on the QWERTY keyboard: recon uses `checkLetterShortcutPress()` (throttled ~80ms).

## Protocol anchoring — Meshtastic firmware source

**Anchored against release `v2.7.26.54e0d8d` (master commit `86fd2069` at read time).** Every constant
below was read from the actual firmware source (fetched from raw.githubusercontent.com), not memory.
Files read: `src/mesh/CryptoEngine.cpp/.h`, `src/mesh/Channels.cpp/.h`, `src/mesh/RadioInterface.cpp/.h`,
`src/mesh/MeshRadio.h`, `src/mesh/SX126xInterface.cpp`, `src/mesh/RadioLibInterface.h`,
`meshtastic/protobufs/meshtastic/portnums.proto`.

### Region EU_868 (`RadioInterface.cpp` `RDEF(EU_868, ...)`)
`RDEF(EU_868, 869.4f, 869.65f, 10, 0, 27, false, false, false)` →
freqStart 869.4, freqEnd 869.65, **dutyCycle 10%**, spacing 0, powerLimit 27 dBm. (SX1262 caps at
+22 dBm — cap `setOutputPower` there.)

### Modem presets (`MeshRadio.h` `modemPresetToParams`, wideLora=false for EU868)
| Preset | BW kHz | SF | CR |
|---|---|---|---|
| ShortFast | 250 | 7 | 4/5 |
| MediumFast | 250 | 9 | 4/5 |
| **LongFast (default)** | **250** | **11** | **4/5** |
| LongModerate | 125 | 11 | 4/8 |
| LongSlow | 125 | 12 | 4/8 |

All match the brief §9 table.

### Frequency slot (`RadioInterface.cpp`)
`numChannels = floor((freqEnd-freqStart)/(spacing + bw/1000)) = floor(0.25/0.25) = 1`.
`channel_num = hash("LongFast") % numChannels = 0x08 % 1 = 0`.
`freq = freqStart + bw/2000 + channel_num*(bw/1000) = 869.4 + 0.125 + 0 =` **869.525 MHz**. ✓

### PHY LoRa settings
- Sync word **`0x2b`** (`RadioLibInterface.h:84 const uint8_t syncWord = 0x2b;`). Passed to RadioLib
  `setSyncWord(0x2b)` — same RadioLib API Bruce already uses, so byte-compatible.
- Preamble length **16** (`RadioInterface.h:98`).
- **CRC ON** (`SX126xInterface.cpp:201 setCRC(RADIOLIB_SX126X_LORA_CRC_ON)`).
- Explicit header, standard IQ (uplink).

### On-air frame = PacketHeader (16 bytes, LE) + AES-CTR ciphertext
`RadioInterface.h` `PacketHeader` — layout confirmed exactly as brief §9:
| Off | Size | Field |
|---|---|---|
| 0 | 4 | `to` (LE) — 0xFFFFFFFF = broadcast |
| 4 | 4 | `from` (LE) |
| 8 | 4 | `id` (LE) — crypto nonce input |
| 12 | 1 | `flags` — bits0-2 hop_limit, bit3 want_ack, bit4 via_mqtt, bits5-7 hop_start |
| 13 | 1 | `channel` — channel-hash byte |
| 14 | 1 | `next_hop` (0 if unknown) |
| 15 | 1 | `relay_node` (0 if unknown) |
Flag masks confirmed: `HOP_LIMIT_MASK 0x07`, `WANT_ACK_MASK 0x08`, `VIA_MQTT_MASK 0x10`,
`HOP_START_MASK 0xE0`, `HOP_START_SHIFT 5`.

### Channel hash (`Channels.cpp` `generateHash` / `xorHash`)
`hash = xorHash(name) ^ xorHash(psk)`, `xorHash` = XOR of all bytes. For name `"LongFast"` +
default PSK: `xorHash("LongFast")=0x0A`, `xorHash(defaultpsk)=0x02` → **channel hash = 0x08**.
(Verified independently in Python.)

### Default channel key (PSK index 1) (`Channels.h:144 defaultpsk[]`)
```
d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01   (AES-128, 16 bytes)
```
Expansion (`Channels.cpp getKey`): psk.size==1 → index byte. index 0 = no encryption; index 1 =
defaultpsk verbatim; index N = defaultpsk with **last byte += (N-1)**. Confirmed.

### AES-CTR nonce (`CryptoEngine.cpp` `initNonce` + `encryptAESCtr`)
`encryptPacket(fromNode, packetId, ...)` → `initNonce(fromNode, packetId)` (extraNonce defaults 0):
```
memcpy(nonce,   &packetId, 8);   // uint64 LE  (our 32-bit id zero-extended)
memcpy(nonce+8, &fromNode, 4);   // uint32 LE
// nonce[12..15] = 0
```
So the 16-byte IV/counter block = `id[0..3] LE | 00 00 00 00 | from[0..3] LE | 00 00 00 00`.
`encryptAESCtr`: `CTR<AES128>`, `setIV(nonce,16)`, `setCounterSize(4)` → the **last 4 bytes** are the
incrementing counter, high 12 bytes fixed. Decrypt == encrypt (CTR). `MAX_BLOCKSIZE` gate.

**mbedtls compatibility note (critical):** `mbedtls_aes_crypt_ctr` increments the *entire* 16-byte
nonce_counter as a 128-bit big-endian counter. Meshtastic (rweather CTR, counterSize=4) increments
only the last 4 bytes. These are **identical** as long as the last-4-byte counter never overflows
into byte 11 — i.e. for any packet under 2^32 blocks, always true here (max payload ~237 B ≈ 15
blocks). Since bytes 12-15 start at 0, mbedtls's big-endian carry only ever touches byte 15 then 14…
matching rweather exactly. So **mbedtls AES-CTR is byte-compatible** for this use. Validated by KAT below.

### Data protobuf (`mesh.proto` message `Data`)
`portnum` = field 1 (varint), `payload` = field 2 (length-delimited bytes). `PortNum` (portnums.proto):
`UNKNOWN_APP=0, TEXT_MESSAGE_APP=1, REMOTE_HARDWARE_APP=2, POSITION_APP=3, NODEINFO_APP=4,
ROUTING_APP=5, ADMIN_APP=6`. For a text message: field1=1, field2=UTF-8 text. Hand-rollable
encode/decode with a tiny varint + length-delimited reader. Ignore unknown fields; never over-read.

## Self-test vectors (deterministic, generated — not hand-fabricated)

### A.1 Data protobuf — "hi"
`Data{portnum=1, payload="hi"}` = `08 01 12 02 68 69` (6 bytes). Hand-verified against wire format.

### A.2 Default key — see above (assert PSK-expansion of index 1 == defaultpsk).

### A.3 Channel hash LongFast = **0x08** (derived, verified in Python).

### A.4 AES-CTR KATs (generated with `openssl enc -aes-128-ctr`)
Key `d4f1bb3a20290759f0bcffabcf4e6901`, nonce/IV `cdab0000000000007856341200000000`
(id=0x0000ABCD, from=0x12345678):
- **Single-block:** pt `080112026869` → ct `4d7577d5e002`.
- **Multi-block (21 B, crosses block boundary):** pt `0801121148656c6c6f204d65736874617374696321`
  ("Hello Meshtastic!") → ct `4d7577c6c00e0100bb3e87cbe91c868e5769652ac0`.
  (First 3 ct bytes match the single-block ct — same keystream block 0 — confirming counter/IV setup;
  the boundary-crossing bytes prove mbedtls's counter increment matches Meshtastic's.)
Firmware self-test must: reproduce both ciphertexts from plaintext, and decrypt both back.

### A.5 Header pack/unpack
`to=0xFFFFFFFF, from=0x12345678, id=0x0000ABCD, hop_limit=3, channel=0x08, next_hop=0, relay_node=0`
→ 16 LE bytes `ff ff ff ff 78 56 34 12 cd ab 00 00 03 08 00 00` → round-trips. 10-byte buffer rejected.

## Phase 1 (baseline) — DONE
`pio run -e lilygo-t-deck-pro` on the `lora-recon` base: SUCCESS, Flash 79.2% / RAM 38.6%. Flashed;
clean boot over serial (SDCard mounted, config JSON dumped), identical to the known-good recon build.

## Phase 2 (menu stub) — DONE
`"Meshtastic"` entry added to `LoRaMenu::optionsMenu()`; `src/modules/lora/Meshtastic.{h,cpp}` with a
placeholder `meshtasticChannel()`. User confirmed on-device: entry appears, screen opens, Backspace exits.

## Phase 3 (radio bring-up, RX) — DONE + real-frame validation
Independent `SX1262` (own `Module`/instance, like recon) brought up in the LongFast config:
869.525 MHz, SF11, BW250, CR4/5, sync `0x2b`, preamble 16, CRC on, standard IQ, PA capped +22 dBm
(set now for Phase 5; RX-only this phase — no `transmit()` call). Interrupt-driven continuous RX
(ISR flag + `readData` + `startReceive` re-arm), every frame logged `[Meshtastic] RX #N len rssi snr
airtime crc hex`, 3 s heartbeat.

**Verified on hardware — and better than the checkpoint required:** radio inits cleanly (heartbeats
alive), *and a real Meshtastic frame was captured off the air* despite "no peer" — there is ambient
LongFast traffic in range. The captured frame:
```
FFFFFFFF 9018AD08 F1A77E1A E5 08 00 00  <34B ciphertext>
to=broadcast from=0x08AD1890 id=0x1A7EA7F1 flags=0xE5(hop_limit5,hop_start7) channel=0x08 nh=0 rn=0
```
**channel byte = 0x08 matches our computed LongFast hash against real traffic.** Decrypting the
ciphertext offline (openssl, default key, nonce = id||from||0) yields a valid `Data` protobuf:
`portnum=3 (POSITION_APP)`, 28-byte Position payload, `field9=1`. This pre-validates the *entire*
Phase-4 decode chain (header layout, channel hash, nonce, PSK, AES-128-CTR, Data protobuf) against
live over-the-air data.

**Implication:** the RX/decrypt direction is testable against ambient traffic even without the user's
own node. Only the TX→peer direction (Phase 7) still strictly needs the user's Meshtastic node/app.

## Phase 4 (framing + crypto + protobuf decode + self-test) — DONE
New `src/modules/lora/MeshtasticCodec.{h,cpp}` (pure data-plane, no radio/display, unit-testable):
header pack/unpack, PSK expansion, channel hash, AES-CTR nonce, AES-128-CTR (mbedtls
`mbedtls_aes_crypt_ctr`), minimal `Data` protobuf encode/decode (varint + length-delimited, bounds-
checked, skips unknown fields, never over-reads). RX path in `Meshtastic.cpp` now: unpack header →
log → filter on channel==0x08 → decrypt with LongFast key → decode Data → surface TEXT by portnum.

`runMeshtasticSelfTest()` runs on every module open (Appendix A):
- protobuf(hi) encode==`08 01 12 02 68 69` + decode + empty-payload + trailing-unknown-field
- psk-expand (index 1==defaultpsk, index 2 last byte 0x02, index 0 => len 0)
- channel-hash("LongFast", defaultpsk)==0x08
- aes-ctr KAT: nonce layout + single-block ct `4d7577d5e002` + multi-block ct
  `4d7577c6c00e...652ac0` (both openssl-generated) + round-trips
- header pack/unpack == `ff ff ff ff 78 56 34 12 cd ab 00 00 03 08 00 00` + 10-byte reject
- negative/edge: truncated protobuf rejected, non-text portnum surfaced by number

**Verified on hardware:** `self-test PASSED` (all 6). And a real ambient frame decoded live:
`from=!04b026e8 ch=0x08 hop=2/7 -> portnum=4 (NODEINFO) payloadLen=83`. Full decrypt+decode chain
confirmed end-to-end against over-the-air traffic. (No TEXT frame happened nearby during the window;
text path is identical decode + the self-test covers text extraction.) mbedtls AES-CTR is confirmed
byte-compatible with Meshtastic in practice (real frames decrypt to valid protobufs).

## Phase 5 (encode + TX + duty-cycle guard + loopback) — DONE
- **Node-ID:** derived from ESP32 efuse MAC low 4 bytes (`deriveNodeId()`), stable across boots
  without extra storage; displayed `!%08x` (this device: `!d69fc114`). Avoids 0/broadcast.
- **`sendMeshText()`** (the only TX path, user/serial-triggered, never in a loop): encode Data
  (TEXT_MESSAGE_APP) → random non-zero packet `id` (`esp_random`) → AES-CTR encrypt with the
  LongFast key + nonce(ourNode,id) → prepend header (to=broadcast, from=ourNode, id, flags
  `makeFlags(3,false,3)`=0x63 hop_limit3/hop_start3, channel=0x08) → **duty-cycle guard** →
  `transmit()` → re-arm RX.
- **Duty-cycle guard (mandatory, in every TX path):** `meshtastic::DutyCycle` rolling-window airtime
  tracker (1 h window, 10% = 360 s budget). `wouldExceed()` blocks before transmit; `msUntilAvailable()`
  reports retry time; airtime from `radio->getTimeOnAir(frameLen)`. Surfaced in the UI as "duty: N%%
  used" / "TX blocked (retry ~Ns)".
- **PA power** capped at +22 dBm (SX1262 max; region limit 27 dBm).
- **Serial-triggered TX:** a line typed on USB serial is sent as a text message (lets sending be
  triggered/observed autonomously; on-screen compose keyboard is Phase 6).

**Verified on hardware:** self-test PASSED all 8 (protobuf, psk-expand, channel-hash, aes-ctr KAT,
header, negative/edge, **tx loopback**, **duty-cycle**). A real transmit succeeded:
`TX #1 id=0x71f952ba len=46 airtime=600ms used=600ms/360000ms "Bruce T-Deck LongFast test"`.
**Offline proof of interop:** reconstructing that exact frame (openssl, same key/nonce) and decoding
it via the stock-node path yields `portnum=1, "Bruce T-Deck LongFast test"` — a stock default-key
node will display it. TX byte-correctness confirmed; only a live peer receiving it (Phase 7) remains
unverified (no peer this session). Duty-cycle *blocking* demonstrated deterministically by the
self-test (same `wouldExceed`/`msUntilAvailable` code `sendMeshText` uses).

## Phase 6 (on-screen UI) — DONE
Three views on 320x240, shared chrome (node-ID, LongFast/869.5, duty-cycle %, TX count, RX/TX/BLK
state) + footer hints:
- **Screen A Conversation:** newest at bottom, own msgs `>>` in priColor, others `!from: text` + RF
  tag; trackball up/down scrolls (bottom-anchored, pages toward older); SEL or `c` = compose.
- **Screen B Compose:** modal `keyboard("Type message:")` → `sendMeshText()` (duty-guarded).
- **Screen C Nodes:** `n` opens; node-ID / last RSSI-SNR / count / age, cursor-navigable; `n` or
  Backspace returns. Populated from `from` of every decoded frame.
- Backspace exits from Conversation.

**Flicker fix (same bug recon hit):** first cut redrew whole regions every 1 s tick → user reported
"flapping screen". Fixed with per-row/-line content diffing (`bodyTextCache`/`bodyFgCache`/`bodyBgCache`,
`chromeLineCache`, `footerCache`, reset on view entry): a row is only repainted when its text/colours
actually change; no periodic `fillScreen`/region-fill. **User confirmed smooth, UI + navigation good.**
Verified by driving two serial sends live (TX #1/#2) that appeared as `>>` lines while the user watched.

## Phase 7 (live interop) — GAP (no peer this session)
No Meshtastic peer was available, so full bidirectional interop is **not verified** (a gap, not a
pass). Strong evidence exists both ways though: **RX** — real ambient LongFast frames (NODEINFO,
POSITION) decode correctly off the air; **TX** — the exact frame we transmit, reconstructed offline
with openssl, decodes via the stock-node path to our text, so a stock default-key node will display
it. Revisit with a real node/app on EU_868 / LongFast / default key to close the gap.

## Phase 8 (optional extras) — DONE (user picked: node names + SD logging)
- **Node names (read-only):** `decodeUserName()` in the codec pulls long_name(f2)/short_name(f3) from
  NODEINFO_APP `User` payloads; names shown in the nodes list and as the conversation sender label.
  Self-test `nodeinfo name` case added. **Verified live:** decoded `!1c1612af` = short "AROZ" /
  long "IAPC REV Router" from ambient traffic.
- **SD conversation logging:** best-effort CSV at `/meshtastic_log.csv`
  (`uptime_ms,dir,nodeid,name,rssi,snr,"text"`), appended per RX text and per TX; header written on
  create; silently disabled when no card. All SD access is from the main loop (never the RX ISR), so
  it doesn't race the radio on the shared SPI bus. **Verified:** `SD log: /meshtastic_log.csv` on open.
- Not chosen: selectable modem preset. (Preset is fixed LongFast.)

**Verified on hardware:** self-test PASSED 10/10 (adds `tx loopback`, `duty-cycle`, `nodeinfo name`).

## Phase 9 (polish / cross-board / docs) — DONE
- Cross-board compile check: `lilygo-t-deck` (sibling T-Deck, shares LoRa + the board-ini) SUCCESS
  (Flash 79.6%); `m5stack-cardputer` (different family, no LoRa pins, not LITE) SUCCESS (Flash 78.0%).
  No regression; the module is portable (runtime pin checks, no board-specific hardcoding).
- `lilygo-t-deck-pro` final = Phase 8 build (Flash 79.6% / RAM 39.0%); Phase 9 added docs only, no
  firmware code change, so no reflash needed.
- `docs/meshtastic-README.md` written (feature README deliverable).
- No new format/compile warnings in the Meshtastic sources.

## Phase 10 (post-ship fix) — displayable-text guard on the RX text path
Symptom reported by user: a received frame rendered as "a symbol line" on screen, and the
SD log's rx `text` field held binary bytes (looked like a hexdump). Root cause found by decoding
the on-card `meshtastic_log.csv`: the offending frame was a **NODEINFO `User` record** from node
`waza` (`!6c72ff04`, long_name `waza🇫🇷74` incl. a 🇫🇷 flag emoji, short_name `waza`, macaddr,
hw_model, role, 32-byte public_key) that had been surfaced as if it were message text — so the
protobuf tag bytes + MAC/public-key + emoji drew as symbols and were written into the CSV text field.

Fix: `meshtastic::sanitizeDisplayText(payload, len, out)` in the codec. Keeps printable ASCII
verbatim; collapses `\n`/`\r`/`\t` to a single space (keeps display + CSV single-line); replaces any
valid non-ASCII UTF-8 code point (emoji/accents the device font can't render) with `?`; and returns
**false** on a C0 control byte (other than tab/newline/CR), DEL, or malformed UTF-8 — i.e. binary
payloads (mis-routed protobuf, wrong-key/1-byte-channel-hash-collision garbage). RX text path in
`Meshtastic.cpp` now drops such frames (not shown, not logged). This also fixes the SD log: only clean
text ever reaches `logMeshMsg` now, so the CSV stays human-readable text (no binary blobs).
New self-test case `text guard`. **Verified on hardware:** self-test PASSED 11/11 (adds `text guard`),
flashed to `lilygo-t-deck-pro` (Flash 79.6% / RAM 39.0%), radio up clean.

## Phase 11 — self-NodeInfo broadcast + crypto re-verification

**Self-NodeInfo broadcast (so peers show a name).** Added `meshtastic::encodeUser(id, long, short)`
to the codec (User protobuf: field1 id `0x0a`, field2 long_name `0x12`, field3 short_name `0x1a` —
symmetric with the existing `decodeUserName` which reads f2/f3). New self-test case `nodeinfo name`
now also round-trips `encodeUser` back through `decodeUserName` and asserts the leading id tag
(`0a 09…`). In `Meshtastic.cpp` the Phase-5 send path was refactored into a shared `txMeshData(portnum,
payload, len, reportBlock, label)` core (encode→encrypt→frame→duty-guard→transmit); `sendMeshText`
and the new `sendNodeInfo()` both call it. Names derive from the node-ID at open (short = last 4 hex
`%04x`, long = `Bruce <short>`) — no extra config/storage. `sendNodeInfo()` fires ~8 s after open then
every 30 min (`NODEINFO_INTERVAL_MS`), wrap-safe signed-millis schedule, duty-cycle guarded, and passes
`reportBlock=false` so a deferred announce never shows as a user "TX blocked". Builds clean on
`lilygo-t-deck-pro` (Flash 89.0% OTA). **On-device + live-peer verification still pending** (same
Phase-7 interop gap: needs a real node to confirm it appears named).

**Encryption/decryption re-checked against current Meshtastic `master` (date 2026-07-04).** Re-read
the upstream source and confirmed every constant is still exact: EU_868 `RDEF(869.4,869.65,10,0,27,…)`;
LONG_FAST (wideLora=false) BW250/SF11/CR4:5; preamble 16; `syncWord 0x2b`; `setCRC(…CRC_ON)`;
`PacketHeader` layout + flag masks (`0x07/0x08/0x10/0xE0`, shift 5); `defaultpsk` bytes
`d4f1bb3a…6901`; hash `xorHash(name)^xorHash(psk)` → LongFast `0x08`; `initNonce` = packetId u64 LE @0,
fromNode u32 LE @8, extraNonce @12 (0 for PSK), CTR `setCounterSize(4)`. The fork's TX (`initNonce(us,id)`
→ AES-CTR) and RX (`initNonce(from,id)` → AES-CTR) are symmetric and match; mbedtls CTR stays
byte-identical for our sizes (carry never reaches byte 11). No discrepancy found.

## Phase 12 — overnight RX diagnosis + readability/timestamp fixes

User reported received messages showing only "." on screen. Added an SD raw RX log
(`/meshtastic_raw.log`: full ciphertext hex per frame + decrypted payload hex + the exact display
string) and ran it overnight. **Finding: no decode bug.** `/ping`=`2F70696E67`, `oui`=`6F7569`,
`pong 00:03:29` all decode exactly; the "." messages were literally single-dot transmissions from one
node (`!f6fb4870`), heard over three hops. The real problem was readability: accented UTF-8 (French
mesh traffic) was blanked to `?` — the weather bot's `Météo à Genève : … 23.9°C` rendered as
`M?t?o ? Gen?ve … 23.9?C`.

Fixes shipped:
- **ASCII transliteration** in `sanitizeDisplayText` (`asciiFold`): Latin-1 accents → base letter
  (é→e, à→a, ç→c, ß→ss, …), common punctuation (« » → ", curly quotes → ' / ", – — → -, … → ...,
  € → EUR), ° dropped; only truly unrenderable code points (emoji/CJK, incl. all 4-byte) stay `?`.
  Verified against the real overnight bytes → `Meteo a Geneve : Temperature : 23.9C …`. Self-test
  `text guard` extended with the accent case.
- **Per-message timestamp** on every conversation line: `HH:MM:SS` wall-clock at arrival, or
  `+HH:MM:SS` device uptime when the clock isn't set yet (the '+' marks it relative). `ConvMsg.clk`
  captured in `addConvMsg` via `nowClock()`; also stamped on each raw-log frame (`clk=`).
- **Raw log kept but channel-filtered:** only LongFast-channel frames (`buf[13]==0x08`) are logged, so
  the ~1400 foreign-channel frames/night are dropped; ~1 MB/night of ambient LongFast still accrues,
  deletable anytime. (Candidate future toggle if it becomes a nuisance.)

## Open decisions / to relay to user
- Base branch (main vs lora-recon) — §5.1.
- **Antenna safety:** EU868 antenna MUST be attached before radio power; TX into a missing/mismatched
  antenna can destroy the PA. Confirm before Phase 3.
- Interop gear for Phase 7: a real Meshtastic node/app on EU_868 / LongFast / default key.
- Node-ID source: derive a stable 32-bit ID from the ESP32 MAC, persist it. Display `!%08x`.
