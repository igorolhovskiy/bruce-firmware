# LoRa Recon — investigation notes (pre-Phase 2)

Working notes for the "LoRa Recon" feature (see `bruce-lora-recon-TASK.md` in the parent
folder). Kept here so intermediate findings survive across sessions; will be folded into the
final feature README in Phase 8.

## Toolchain / environment

- PlatformIO's `espressif32` platform requires Python 3.10–3.13. The project's `.pyproject`
  venv (and system `python3`) is 3.14.6 — incompatible.
- Fix: used `uv` (`~/.local/bin/uv`, already installed) to fetch a standalone Python 3.12 and
  created a second venv, **`.pyproject-pio/`**, inside this project folder, dedicated to
  PlatformIO. `.pyproject` itself is untouched.
- All `pio` commands: `source ../.pyproject-pio/bin/activate` (from `bruce-firmware/`) first.
- Serial captured via `pyserial` from the original `.pyproject` venv.

## Target environment

- `$TDECK_ENV = lilygo-t-deck-pro` — confirmed via `platformio.ini:42` comment
  (`;lilygo-t-deck-pro # This is T-Deck Plus!!`) and defined in
  `boards/lilygo-t-deck/lilygo-t-deck.ini:12`
  (`[env:lilygo-t-deck-pro] # T-Deck Plus, need to rename it when merge to MAIN`).

## Baseline checkpoint (Phase 1) — DONE

- `pio run -e lilygo-t-deck-pro` — SUCCESS (Flash 78.5%, RAM 38.0%).
- `pio run -e lilygo-t-deck-pro -t upload --upload-port /dev/ttyACM0` — SUCCESS.
- Serial banner clean: ESP-ROM boot, SD card mounted, config JSON dumped, no crash.
- Screen confirmed showing normal Bruce main menu by user.

## LoRa pin config

Bruce's on-device default config for this board already has correct SX1262 pins (dumped live
from serial JSON, key `LoRa_Pins`):

```
sck: 40, miso: 38, mosi: 41, cs: 9, io0(RST): 17, io2(IRQ/DIO1): 45
```

This matches the task brief's §3 pin table exactly. Backed by `bruceConfigPins.LoRa_bus`
(`src/core/configPins.h:66-91`, populated from `-DLORA_SCK/MISO/MOSI/CS/RST/DIO0` build flags
in `boards/lilygo-t-deck/lilygo-t-deck.ini`, editable at runtime via Config → LoRa Pins,
`src/core/menu_items/ConfigMenu.cpp:268`).

**Gap found:** `LORA_BUSY` (GPIO 13, SX1262 BUSY pin per task §3) is **not defined** anywhere
in `boards/lilygo-t-deck/lilygo-t-deck.ini`. `src/modules/lora/LoRaRF.cpp:56-61`
(`getLoraBusyPin()`) falls back to `GPIO_NUM_NC` when `LORA_BUSY` is undefined, and
`startLoraRadio()` just prints a warning and continues. **Plan:** add `-DLORA_BUSY=13` to
`boards/lilygo-t-deck/lilygo-t-deck.ini`'s `[env:lilygo-t-deck-pro]` build_flags in Phase 3 —
board config, not hardcoded in module code, per task guidance.

`jgromes/RadioLib @ ^7.4.0` (`platformio.ini:210`) — SX1262 already supported, already used by
`LoRaRF.cpp`.

## Menu system

- Base class: `include/MenuItemInterface.h:7` — pure virtuals `optionsMenu()`, `drawIcon()`,
  `hasTheme()`, `themePath()`; non-virtual `draw()`/`drawArrows()`/`drawTitle()`/`getName()`
  provided by the base.
- Existing `LoRaMenu` (`src/core/menu_items/LoRaMenu.h/.cpp`) has a submenu with
  Chat / Change username / Change Frequency, calling into `src/modules/lora/LoRaRF.cpp`'s
  `lorachat()` etc. Whole module gated `#if !defined(LITE_VERSION)`.
- **Chosen extension point:** add a `"Recon"` entry to `LoRaMenu::optionsMenu()`'s `options`
  vector (`LoRaMenu.cpp:8-12`) calling a new `loraRecon()` function declared in `LoRaMenu.h`
  and implemented in `LoRaRF.cpp`. No new class, no main-menu registration changes needed.
- Registered in `src/core/main_menu.h:15,39` / `main_menu.cpp:13` (`&loraMenu` pushed into the
  `_menuItems` vector) — unaffected by our change.

## Display API

- `tft` global (`include/globals.h:44`); primitives: `fillRect`, `drawCentreString`,
  `drawWideLine`, `drawArc`, `setTextSize`, `setTextColor`, `drawString`, etc.
- Canonical scrollable list: `loopOptions()` (`src/core/display.h:164`, impl
  `display.cpp:468+`) — used by every menu/submenu/pin-picker in the codebase.
- Ready-made scrolling log widget: `ScrollableTextArea`
  (`src/core/scrollableTextArea.h/.cpp`) — `scrollUp()/scrollDown()/addLine()/draw()/show()`.
  Good candidate for the captured-frames list (Phase 6, Screen B).
- `tftWidth`/`tftHeight` globals (`globals.h:94`), updated on rotation change; 320×240
  landscape confirmed via board's `-DROTATION=1`.

## Input API

- `volatile bool` flags in `include/globals.h:190-210`: `NextPress`, `PrevPress`, `SelPress`,
  `EscPress`, `AnyKeyPress`, `LongPress`, etc.
- Polled via `check(flag)` (`globals.h:223`) — resets flag, standard idiom.
- No blocking "wait for key" primitive; modules run their own
  `while(1) { ...; if (check(EscPress)) break; }` loop (same pattern `loopOptions` uses
  internally).

## Everything lines up with the task brief

No design surprises requiring a decision yet. Proceeding to Phase 2 (menu entry stub).

## Phase 2 (menu entry stub) — DONE

Added `"Recon"` entry to `LoRaMenu::optionsMenu()`, new `src/modules/lora/LoRaRecon.{h,cpp}`
with a placeholder `loraRecon()`. Verified on hardware: entry appears in LoRa submenu,
placeholder screen renders, and **the T-Deck's "back" key is physical Backspace/Delete (⌫),
not a labeled Esc** — Bruce maps `keyValue == 0x08` → `KeyStroke.del` → `EscPress`
(`boards/lilygo-t-deck/interface.cpp`). Worth remembering for all future UI phases.

## Phase 3 (promiscuous single-channel RX) — DONE

- Added `-DLORA_BUSY=13` to `boards/lilygo-t-deck/lilygo-t-deck.ini` (`[env:lilygo-t-deck-pro]`)
  — closes the pin gap noted above. Note: changing `build_flags` invalidates scons's whole
  object cache, so this triggered a full rebuild (same duration as the original baseline).
- Exposed `LoRaRF.cpp`'s pin/SPI-bus helpers (`getLoraIrqPin/BusyPin/ResetPin/CsPin`,
  `selectLoraSPIBus`) via `LoRaRF.h` so `LoRaRecon.cpp` reuses the *exact* bring-up logic
  (including the T-Deck's shared TFT/SD/CC1101 SPI bus handling) via its own independent
  `SX1262`/`Module` instance — no shared mutable state with the chat module.
  `LoRaRecon.cpp` never calls a transmit API (verified by grep as part of the commit).
- Fixed test config: 868.1 MHz, SF7, BW125, CR4/5, preamble 8, LoRaWAN public sync `0x34`.
  CRC is left at RadioLib's default (already ON from `begin()`); on `RADIOLIB_ERR_CRC_MISMATCH`
  the buffer is still read and logged (RadioLib's `SX126x::readData` populates `data` before
  checking CRC either way) — malformed frames are visible, not dropped.
- Every frame logs to serial: `[LoRaRecon] RX #N len=.. rssi=..dBm snr=..dB airtime=..ms
  crc=OK|MISMATCH hex=..`. A 3s heartbeat (`listening... packets=N uptime=Ns`) proves the
  loop and radio are alive even with zero traffic.
- **Verified on hardware:** clean boot, radio initializes without error (heartbeats prove
  this — a failed init sits in an error loop with no heartbeat output), Backspace exits
  cleanly. **Not yet verified:** real-frame capture — no transmitter (Meshtastic node,
  LoRaWAN device, or beacon board) was available this session. 0 packets on the fixed
  868.1MHz/SF7/sync-0x34 config is expected without a matching transmitter nearby (task
  brief §10 calls this out explicitly as not-a-bug). **Follow-up:** when a transmitter is
  available, retune (temporarily, for a manual test) to confirm the RX chain captures real
  frames before trusting Phase 5's sweep engine end-to-end. The user has Meshtastic tooling
  installed (`meshtastic`, `mesh-analysis`, `mesh-tunnel` in `.pyproject`) but no node was
  on hand at test time — worth asking again later.

## Phase 4 (parser + self-test) — DONE

Added `src/modules/lora/LoRaWANParser.{h,cpp}`: decodes MHDR/DevAddr/FCtrl/FCnt/FOpts (1.0.x
plaintext, by CID, direction-aware Req/Ans)/FPort/JoinEUI/DevEUI/DevNonce; FRMPayload kept as
opaque length+pointer only; MIC bytes extracted, never validated. `runLoRaWANParserSelfTest()`
runs the Appendix A vectors (+ truncated-data/truncated-join/proprietary edge cases) every time
the Recon screen opens — **verified PASSED on-device** (serial: "self-test PASSED
(join-request, unconfirmed-up, confirmed-up, truncated + proprietary edge cases)"; on-screen
green "parser self-test: OK", both user-confirmed).

## Phase 5 (sweep/lock engine) — DONE

State machine cycles 8 EU868 channels x SF7-12 per the dwell table (400s/full sweep), parks
on RX2 (869.525MHz/SF12, inverted IQ) between sweeps, retunes the already-running radio
in place (`standby → setFrequency/setSpreadingFactor/invertIQ → startReceive`, never a
transmit call). Lock mode (fix SF, hop channels — the brief's recommended variant) toggles on
the trackball's center/Select button. **Verified on hardware:** serial shows the sweep
advancing on schedule (channel 2/8 SF12 appeared ~58s in, matching dwell-table math), lock
toggle logs correctly, on-screen "CH x/8 freq SF" status line updates live.

**Still open:** live-capture-during-sweep hasn't been confirmed with a real transmitter (same
gap as Phase 3 — no Meshtastic node/LoRaWAN device was available this session). Worth revisiting
once one is on hand, since the sweep's per-combo stats (packet count, last RSSI, last DevAddr)
and the RX2 counter are currently untested against live traffic, only against the state-machine
timing itself.
