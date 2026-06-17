# TSL6 Firmware Internals

Component-level documentation of the TSL6 runtime and boot firmware, derived by
static analysis of the archived images. The goal is a complete enough picture to
understand, edit, and eventually rewrite the firmware now that the original
project is abandoned.

All offsets in this document are **payload offsets** (stripped image, base 0),
unless explicitly labelled `transport`. See
[ANALYSIS_WORKFLOW.md](ANALYSIS_WORKFLOW.md) for how payload images are produced
from the downloaded transport pages, and [tools/](tools/) for the reproducible
analyzer used here.

Machine-readable companions to this document live in [analysis/](analysis/):

- `memory_map.json` - linker constants and region model
- `command_dispatch.json` - every BLE command and its handler offset
- `action_table.json` - all 253 action stubs, workers, arguments, labels
- `rule_engine.json` - shortcut/rule table structure

## Confidence Labels

- **Confirmed**: directly present in the disassembly.
- **Correlated**: agrees with an independent source (Mini App, backend catalog).
- **Inferred**: a likely interpretation that still needs hardware validation.
- **Unknown**: required for a full rewrite but not yet recovered.

## 1. Platform

| Item | Value | Status |
|---|---|---|
| CPU | WCH CH32V20x QingKe RISC-V | Confirmed |
| ISA | RV32 little-endian, compressed (RVC) enabled | Confirmed |
| BLE library | `CH32V20x_BLE_LIB_V1.3` (string in both images) | Confirmed |
| Runtime payload | 73,728 bytes (72 KiB) | Confirmed |
| Boot payload | 12,288 bytes (12 KiB) | Confirmed |

The disassembler is validated against documented landmarks (reset vector,
action dispatcher, rule engine) and reproduces them exactly.

## 2. Memory Map and Startup

The runtime image begins with a jump to the startup routine:

```text
0x00000: j 0xf89a            ; reset jump
```

The startup routine at `0xf89a` establishes the RISC-V linker constants and
machine state (Confirmed):

| Constant | Value | Meaning |
|---|---|---|
| `gp` (global pointer) | `0x1fffc000` | base for `gp`-relative state block |
| `sp` (stack pointer) | `0x20008000` | top of stack |
| RAM base | `0x20000000` | CH32V20x SRAM |
| Peripheral base | `0x40000000` | CH32V20x peripherals |

Startup performs the standard C runtime bring-up:

1. Copy `.data` from flash to RAM (`gp .. gp+0xa8`).
2. Zero `.bss` (`gp+0xa8 .. 0x1fff509e`).
3. Program CSRs: `0xbc0=0x1f`, `0x804=3`, set `mstatus`, set `mtvec` (vectored,
   mode 3), then `mret` into the application via `mepc`.

The boot image uses the same pattern with `gp=0x20003000`, `sp=0x2000f000`, and
reset jump `0x0000 -> 0x1c28`.

### Resident vs. updatable code

The downloadable runtime image is **self-contained application code** in the
range `0x0-0x12000`. A small number of control-flow targets point above the
image; these are entry points into a resident BLE stack / bootloader region that
the server image does not contain. Practically:

- The server `isapp=1` image is the **application/runtime slot** only.
- Hardware drivers and the BLE controller stack referenced during startup are
  **not** in this image and must be recovered separately (physical flash dump)
  before a full rewrite. (Unknown)

`gp`-relative addressing is used throughout for the BLE state block, including
the 256-byte shortcut table at `gp+0x80` (see section 6).

## 3. BLE Transport and Frame Parser

Recovered from the Mini App and consistent with the firmware (Confirmed):

- GATT service `FFF0`, characteristic `FFF1` (notify + write).
- Application frame:

  ```text
  55 7F TYPE LEN_H LEN_L PAYLOAD... CHECKSUM
  ```

- Checksum = `sum(TYPE, LEN_H, LEN_L, payload) mod 256`.
- Frames may span multiple BLE writes; the parser resets if >500 ms elapses
  between chunks. Maximum payload length 4096 bytes.

## 4. Main Command Dispatcher

Entry: `0xbdea` (Confirmed). The received command byte is held in register `s1`
and routed through a **balanced binary-search comparison tree**. Equality
outcomes select handlers; range comparisons (`bltu`/`bgeu`) are tree
navigation. Unknown commands fall through to `0xbcba`.

Full command -> handler table (payload offsets). See
`analysis/command_dispatch.json` for the generated source of truth.

| Cmd | Handler | Purpose | Status |
|---:|---:|---|---|
| `0xA0` | `0xbe3e` | Module status/info (builds reply via `0xb7c6`) | Confirmed |
| `0xA1` | `0xbe7c` | Setting/control family | Correlated |
| `0xA2` | `0xc53c` | Momentary steering-wheel button (values 1-5) | Confirmed |
| `0xA3` | `0xbeae` | Control family | Correlated |
| `0xA4` | `0xc57e` | Control family | Correlated |
| `0xA5` | `0xc594` | Module reboot | Correlated |
| `0xA6` | `0xbfb4` | AP automatic behavior | Correlated |
| `0xA7` | `0xc52a` | Immediate vehicle control | Correlated |
| `0xA9` | `0xc5d4` | BLE password change | Correlated |
| `0xAA` | `0xbe12` | Internal/aux | Inferred |
| `0xAB` | `0xbfd2` | Shortcut trigger/action table (read needs payload `2`) | Confirmed |
| `0xAF` | `0xc7f8` | Authorization/activation | Correlated |
| `0xB0` | `0xc00a` | Dashboard telemetry (payload `1` enable, `0` disable) | Confirmed |
| `0xB9` | `0xc702` | RGB/ambient-light config | Confirmed |
| `0xBA` | `0xc68a` | BLE-button config | Confirmed |
| `0xBB` | `0xc034` | Execute/test one action via action dispatcher | Confirmed |
| `0xC0` | `0xc2ee` | CAN debug transport | Confirmed |
| `0xC1` | `0xc4fa` | Vehicle type query | Confirmed |
| `0xD0` | `0xc060` | Internal command family | Inferred |
| `0xD1` | `0xc2da` | Internal command family | Inferred |
| `0xD2` | `0xc08c` | Internal command family | Inferred |
| `0xF0` | `0xc0ee` | Internal/diagnostic | Inferred |

The `0xA0` handler reply builder also dispatches sub-commands `0xAD`, `0xAE`,
`0xA8` (factory/authorization/password-verify) seen at `0xbcc8..`.

## 5. Steering-Wheel / Media Keycode Primitive

The `0xA2` handler (`0xc53c`) reads payload byte 0, validates `1..5`, and (for
`1..4`) tail-calls the shared keycode primitive at **`0x33e2`** (Confirmed).

`0x33e2` validates a keycode in `1..18`, performs the action, and stores the
keycode into a RAM state byte at `0x20003f2c` (`auipc a5,0x20001; sb s0,
-0x4e0(a5)`). This single
primitive is reused by most of the media/AP/steering action handlers (section
6), which is why those actions are parameterized tail-calls rather than distinct
code.

## 6. Action Dispatcher and Table

Entry: `0xd16e`. Algorithm (Confirmed):

```text
index = (action_id - 1) & 0xFF
if index > 0xFC: reject
target = TABLE_BASE + s32(TABLE_BASE + index*4)
jump target
```

`TABLE_BASE = 0x11710`, computed from `auipc a4,4; addi a4,a4,0x530` at
`0xd1e0`. The table holds **253 entries**. Each entry points to a short stub
that restores the dispatcher frame, loads 0-3 small immediate arguments into
`a0..a3`, and tail-calls a shared worker.

`analysis/action_table.json` lists every stub, its worker, arguments, and
(where known) the backend catalog label. Key structural findings:

- **42 actions** share a single default/no-op stub (worker `None`): these IDs
  are unimplemented placeholders.
- Actions **1-8** call worker `0xf296` with a one-hot bitmask
  (`1,2,4,8,16,32,64,128`): a bitfield control register.
- Actions **137-149** (the media/AP cluster) mostly tail-call the keycode
  primitive `0x33e2` with a keycode in `a0`:

  | Action | Catalog label | Keycode (a0) |
  |---:|---|---:|
  | 137 | AP speed +5 | 17 |
  | 138 | AP speed -5 | 18 |
  | 139 | Left scroll middle-button hold | (no arg; via `0x3a30`) |
  | 140 | Play/pause | 5 |
  | 141 | Volume +1 | 1 |
  | 142 | Volume -1 | 3 |
  | 143 | Previous track | 4 |
  | 144 | Next track | 2 |
  | 145 | Voice assistant | (no arg) |
  | 146 | AP speed +1 | 9 |
  | 147 | AP speed -1 | 11 |
  | 148 | Following distance +1 | 12 |
  | 149 | Following distance -1 | 10 |

- Action **139** is special: its stub tail-calls `0x3a30` (not the keycode
  primitive), which writes `0x0C` to a RAM state byte. This latches a
  steering-wheel hold operation; the downstream consumer/timing is still
  Unknown.

Trigger IDs and action IDs are **separate namespaces**. Trigger 139 means
"speed 5-10"; action 139 means "left scroll hold". Tools must not share one
label map.

## 7. Shortcut Rule Engine

Entry: `0xe310` (Confirmed). It scans three tables when an incoming trigger
arrives:

1. **Primary table** at `gp+0x80`, 256 bytes: scanned `0..0xFE` step 2. Byte
   `N` is a trigger, byte `N+1` an action. On match it calls the action
   dispatcher (`0xd16e`) with the action byte. 127 usable pairs. No delay,
   sequence, or pointer fields exist in a stored rule.
2. **Secondary table** at `gp+0x84`: 36 entries, 7-byte stride. A 9-bit trigger
   is assembled from the first two bytes; bit 1 of the second byte gates the
   operation.
3. **Tertiary table** at `gp+0x88`: same layout as the secondary table.

Because each matched primary rule emits exactly one action byte, an autonomous
multi-step macro (e.g. "hold, wait 0.5 s, select") **cannot** be represented in
the existing table. It requires either a firmware change or a single existing
action that performs the whole sequence internally.

## 8. Firmware Update Path

Separate update dispatcher at `0xbc76` (Confirmed). It selects on the command
byte and accepts `0x57` (write), `0x53` (start), `0x55` (prepare), `0x45`
(finalize); a related path uses `0x52` (read/verify). All converge on a worker
at `0x1bc8`.

This confirms the safety boundary in the README and `CLEAN_ROOM_SPEC.md`: the
page-read `0x52` is part of the update flow, not a standalone safe backup API.
Do not exercise these commands without a recovery path and sacrificial hardware.

## 9. Dashboard Telemetry

The `0xB0` handler (`0xc00a`) reads payload byte 0 (`1` enable, `0` disable),
then calls the status builder `0xb7c6` and the telemetry producer `0xb86e`. The
returned >=33-byte packed layout (speed, gear, signals, SoC, tire pressures,
powers, temperatures, etc.) is documented field-by-field in
[CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) section 8.

## 10. BLE HID Device Names

The runtime string table contains BLE peripheral names: `KRemote`,
`Insta360 GPS Remote`, `BT KeyBoard`, `MK424`, `MINI_KEYBOARD`, `BLE-M3`,
`Yiser-J6`, `Free 2`, `WiWU-WM105`, `COIDEA KM`, plus the default BLE password
`1234`. This indicates the firmware also operates as a BLE HID central that
recognizes specific remotes/keyboards and maps their input into the action
system. (Correlated; exact binding logic not yet traced.)

## 11. Open Items for a Full Rewrite

- Recover the resident BLE-stack/bootloader region (physical flash dump).
- Confirm action 139's RAM state byte consumer and timing.
- Identify the non-blocking timer/work-queue primitive (needed for safe macros).
- Map CAN signal extraction per supported vehicle profile (`0xC0`/`0xC1`).
- Determine flash layout, image validation, and boot-slot selection.

See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the chronological
evidence trail and [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) for the rewrite
compatibility contract.
