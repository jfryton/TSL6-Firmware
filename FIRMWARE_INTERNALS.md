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
- `command_dispatch.json` - every BLE command and its handler offset, plus the
  shared reply/TX helpers and the resident BLE-stack vtable slots
- `action_table.json` - all 253 action stubs, workers, arguments, labels
- `rule_engine.json` - shortcut/rule table structure
- `telemetry.json` - dashboard packet field map (getter/width/shift per field)
- `functions.json` - recovered function inventory and call graph (419 runtime
  functions) from `tools/functions.py`
- `boot.json`, `boot_functions.json` - bootloader structure and flash update
  flow (see [BOOTLOADER.md](BOOTLOADER.md))

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

### Handler details (confirmed by disassembly)

- **`0xA1`** (`0xbe7c`): validates via `0x1a6`, then emits a `0x12c`-byte (300)
  reply through the TX framer `0x110a` - a bulk settings/state dump.
- **`0xA5`** (`0xc594`): reboot path; validates via `0x12d4` then issues a reset.
- **`0xA9`** (`0xc5d4`): BLE password change. Operates on the BLE context block
  at `gp+0x74` (offsets `+0x12`/`+0x16` for old/new 4-char strings).
- **`0xAF`** (`0xc7f8`): authorization/activation; requires sub-command `2`,
  then reads a 16-bit token from the payload.
- **`0xB9`** (`0xc702`): RGB/ambient-light config with sub-modes `0`-`3`.
- **`0xBA`** (`0xc68a`): BLE-button config; sub-command `2` is the read path.
- **`0xC0`** (`0xc2ee`): CAN debug/control. Sub-command `0` disables, `1`
  enables the CAN channels (via `0xa756` for channels 0/1/2), `2` selects an
  alternate mode (`0xa72a`), and `0xFF` is an extended debug mode. CAN channel
  control flows through `0x83d2`/`0xa698`.
- **`0xC1`** (`0xc4fa`): vehicle-type query; reads the type via `0xc89e` and
  replies with a 4-byte payload through reply builder `0xb76c`.

## 5. Steering-Wheel / Media Keycode Primitive

The `0xA2` handler (`0xc53c`) reads payload byte 0, validates `1..5`, and (for
`1..4`) tail-calls the shared keycode primitive at **`0x33e2`** (Confirmed).

`0x33e2` validates a keycode in `1..18`, performs the action, and stores the
keycode into a RAM state byte at `0x20003f2c` (`auipc a5,0x20001; sb s0,
-0x4e0(a5)`). This single
primitive is reused by most of the media/AP/steering action handlers (section
6), which is why those actions are parameterized tail-calls rather than distinct
code.

## 5a. BLE Transmit Path and Resident Stack Vtable

Outbound BLE frames are built and queued by a small set of shared helpers
(Confirmed):

| Helper | Role |
|---:|---|
| `0x110a` | Async TX framer/enqueue. Manages a 15-slot ring (12 bytes/slot) at RAM `0x20003e28`, then dispatches via a resident notify pointer. 33 call sites - the core send routine. |
| `0xb76c` | Generic command reply builder. Allocates a buffer via a resident pointer, fills `command`/`length`/`payload`, and enqueues through `0x110a`. |
| `0xb7c6` | Module status reply builder (used by `0xA0`, `0xB0`). |
| `0xb86e` | Dashboard telemetry producer; emits the 35-byte `0xB0` packet, rate-limited using a timestamp at `gp+0x178`. |
| `0xbdb8` | Reply tail shared by the `0xA2`/`0xBB` handlers. |

These helpers reach hardware through a **resident BLE-stack vtable** at
peripheral base `0x40000000`. The firmware loads a function pointer with
`lui 0x40` + offset and calls it indirectly (`jr`/`jalr`). Confirmed slots:

| Slot | Use |
|---|---|
| `0x40000050` | BLE notify/send entry (used by the TX framer `0x110a`). |
| `0x40000070` | Buffer allocator (used by the reply builder `0xb76c`). |

This is direct evidence that hardware and the BLE controller live in a resident
region outside the downloadable application image (see section 2).

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
  primitive), which writes `0x0C` (12) to a countdown byte at RAM
  `0x20003f2d`. A **periodic handler** decrements that byte at `0x3ce0`; when it
  expires the handler sets a state bit (`|= 0x40`) in an adjacent structure.
  This is a timed steering-wheel hold/release: action 139 latches a 12-tick
  hold and the periodic task releases it. The exact tick period and the final
  vehicle-side effect are still Inferred (need live correlation), but the
  scheduling mechanism is now identified - it is the same periodic-task model a
  rewrite would reuse for non-blocking macros.

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

### Trigger event sources

The engine's `a0` argument is an 8-bit **event code**. `tools/map_rule_triggers.py`
finds all **33** call sites that raise an event
([analysis/rule_triggers.json](analysis/rule_triggers.json)): **22** pass a
constant code (a fixed signal transition), and 11 compute the code from a decoded
signal enum at runtime (e.g. a gear/autopilot state value). Several sites sit
directly inside the per-CAN-ID decoders from section 10b, confirming the
end-to-end path **CAN frame -> signal decode -> event code -> rule table ->
action**. Examples attributed to their source decoder:

| Call site | Trigger | Source (CAN ID) |
|---|---|---|
| `0x7fd4` | `0x8a` | `0x257` vehicle speed |
| `0x8086` | `0x9f` | `0x257` vehicle speed |
| `0x8112` | computed | `0x257` vehicle speed |
| `0x5300` | `0xa0` | `0x39d` autopilot/steering |
| `0x2a6c` | `0x97` | `0x238` drive inverter |
| `0x6e48` | `0x5d` | `0x339` UI range |

The distinct constant event codes observed are `0x00, 0x01, 0x03, 0x28, 0x2a,
0x2d, 0x2e, 0x32, 0x4a, 0x5a, 0x5b, 0x5d, 0x68, 0x69, 0x6a, 0x6c, 0x8a, 0x97,
0x9f, 0xa0, 0xb4, 0xb6`. These are the values a user shortcut's trigger byte
must match in the `gp+0x80` table.

## 8. Firmware Update Path

The runtime contains a **relay** update dispatcher at `0xbc76` (Confirmed). It
selects on the command byte and accepts `0x57` (write), `0x53` (start), `0x55`
(prepare), `0x45` (finalize); a related path uses `0x52` (read/verify). All
converge on a worker at `0x1bc8` that hands pages to the bootloader.

The **actual flash erase/program/verify is performed by the bootloader**, not
the runtime. The full mechanism - page size check (`0x402`), page-index ->
flash-address mapping, 1 KiB erase granularity, 256-byte program chunks,
word-by-word read-back verification, and the CH32V `0x40022000` flash controller
- is documented in [BOOTLOADER.md](BOOTLOADER.md) and
[analysis/boot.json](analysis/boot.json).

This confirms the safety boundary in the README and `CLEAN_ROOM_SPEC.md`: the
page-read `0x52` is part of the update flow, not a standalone safe backup API.
Do not exercise these commands without a recovery path and sacrificial hardware.

## 9. Dashboard Telemetry

The `0xB0` handler (`0xc00a`) reads payload byte 0 (`1` enable, `0` disable),
then calls the status builder `0xb7c6` and the telemetry producer `0xb86e`. The
returned >=33-byte packed layout (speed, gear, signals, SoC, tire pressures,
powers, temperatures, etc.) is documented field-by-field in
[CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) section 8.

### Packing function and signal getters

The packed bytes are assembled by the telemetry packer at **`0xb3e0`**. It reads
the live vehicle state from a CAN-decoded RAM block (around `0x20003f60`, via a
resident snapshot pointer at `0x40000048`) and builds the packet word-by-word.
For each field it calls a dedicated per-signal getter, masks it to the field
width, shifts it to its bit position, and merges it into the current packet
word. `tools/decode_telemetry.py` extracts this mechanically; the result is in
[analysis/telemetry.json](analysis/telemetry.json).

Confirmed field merges in word 0 (each getter is a small accessor into the
CAN-decoded state block):

| Getter | Width | Shift | Field (per CLEAN_ROOM_SPEC s8) |
|---:|---:|---:|---|
| `0x4d14` | 3 | 9 | gear |
| `0x2900` | 2 | 12 | turn signals |
| `0x2d08` | 2 | 14 | autopilot state |
| `0x5d42` | 4 | 16 | door state |
| `0x51ec` | 7 | 24 | state of charge |

Word 1 packs single-bit appearance/sport/flag fields (getters `0x5bd0`,
`0x76a8`, `0x4162`, `0x5d22`) and the 11-bit inverter powers (`0x7e42`, packed
twice at shifts 8 and 19 for front/rear). Speed (the first 9-bit field) is
packed just before the table above at `0xb40e`. This is direct firmware
confirmation of the dashboard contract; the getters are the authoritative source
of each signal.

## 10. BLE HID Device Names and Name Binding

The runtime string table contains BLE peripheral names: `KRemote`,
`Insta360 GPS Remote`, `BT KeyBoard`, `MK424`, `MINI_KEYBOARD`, `BLE-M3`,
`Yiser-J6`, `Free 2`, `WiWU-WM105`, `COIDEA KM`, plus the default BLE password
`1234`. The firmware advertises as `TSL6` (`0x10e25`) and also operates as a BLE
HID central that recognizes specific remotes/keyboards and maps their input into
the action system.

The binding logic is at **`0x99c0`-`0x9bba`** (Confirmed). On GAP
discovery/connect it compares the peer device name against the fixed identity
list using a resident compare function (loaded as `lw a5,0x3c(0x40000000)` /
`lw a5,0(s6)`), passing the candidate string pointer, the peer name, and the
length. A zero result selects that profile. Confirmed comparisons:

| Name string | Offset | Length | Compare site |
|---|---|---:|---|
| `BT KeyBoard` | `0x11604` | 11 | `0x99ce` |
| `MINI_KEYBOARD` | `0x11620` | 13 | `0x9a54` |
| `BLE-M3` | `0x11630` | 6 | `0x9a6c` |

Full decode in [analysis/internal_commands.json](analysis/internal_commands.json)
(`hid_name_binding`).

## 10a. gp-Relative State Block

All mutable BLE/rule/connection state lives in a single block based at the global
pointer (`gp=0x1fffc000`). `tools/map_state.py` sweeps the whole image and
tabulates every `gp+IMM` reference, recording access widths, read/write counts,
and whether the offset is ever the base of an address-taken sub-structure. The
result ([analysis/state_block.json](analysis/state_block.json)) lists **163**
distinct offsets (121 directly load/stored, 42 address-taken only).

Landmarks confirmed elsewhere line up:

| Offset | Role |
|---|---|
| `gp+0x80` | rule-engine primary shortcut table (256 B, trigger/action pairs) |
| `gp+0x84`, `gp+0x88` | rule-engine secondary tables (36 x 7 B each) |
| `gp+0x108` | gear-change dirty counter (bumped by the gear decoder) |
| `gp+0x178` | telemetry rate-limit timestamp (0xB0 throttle) |
| `gp+0x184`-`gp+0x194` | hottest scalar fields (per-connection/notify state) |

The `address_taken` count distinguishes scalar fields (only loaded/stored) from
structure/array bases passed by pointer (e.g. the rule tables at `+0x80`/`+0x84`/
`+0x88` and the connection table near `+0x74`, referenced 71 times).

## 10b. CAN Receive Path and Signal Cache

Vehicle telemetry originates from a CAN receive decoder, separate from the
gp-block. Decoded scalar signals are written to an **absolute-addressed RAM
signal cache** (`~0x20003e5c`-`0x20003f86`); the dashboard getters in section 9
sample this cache. `tools/map_ramcache.py` maps it
([analysis/ram_cache.json](analysis/ram_cache.json)): 353 distinct RAM addresses,
with the 10 telemetry-sampled slots identified by getter, e.g. gear at
`0x20003f60`, SoC at `0x20003f81`, autopilot at `0x20003f00`, door at
`0x20003f86`.

The CAN-ID dispatcher is at **`0xc934`** (Confirmed). It reads the 11-bit CAN ID
from the frame header (`lhu a5,0(s0)`) and walks a balanced comparison tree;
each matched arm tail-calls a per-ID decoder that extracts bitfields and writes
the signal cache. `tools/map_can.py` recovers the table
([analysis/can_map.json](analysis/can_map.json)): **34** decoded CAN IDs (26 with
inline scalar decoders, 8 copied verbatim into a RAM frame buffer via the shared
raw-frame store `0x28e` for deferred decoding). Example decoders:

| CAN ID | Decoder | Correlated meaning |
|---:|---|---|
| `0x118` | `0x4c58` | DriveSystemStatus (gear/AP) |
| `0x129` | `0x811e` | SteeringAngle |
| `0x132` | raw-store | HV battery (V/I/SoC) |
| `0x257` | `0x7f9a` | vehicle speed |
| `0x352` | raw-store | BMS energy/SoC |

IDs are correlated to community Tesla Model 3/Y bus IDs, not confirmed against
this specific harness. The gear decoder (`0x4c5a`) is the worked example: it
reads frame byte 5, shifts right 5 (top 3 bits), stores to `0x20003f60`, and on
change increments the `gp+0x108` dirty counter.

## 10c. Internal Commands (D0 / D1 / D2 / F0)

Beyond the action and telemetry commands, four control commands manage
notification streams, diagnostics, and provisioning. Full evidence in
[analysis/internal_commands.json](analysis/internal_commands.json).

| Cmd | Handler | Role |
|---|---|---|
| `0xD0` | `0xc060` | Enable/select a per-connection notification stream (payload[0]==1, status setter `0xb7c6` selector 3). Confirmed. |
| `0xD1` | `0xc2da` | Disable that stream (payload[0]==1, `0xb7c6` selector 4). Confirmed. |
| `0xD2` | `0xc08c` | Raw register/diagnostic read: resident slot `0x40000048` fetches 8 bytes, byte-swapped to big-endian halfwords, published via `0x28e`. Correlated. |
| `0xF0` | `0xc0ee` | Configuration/provisioning write: subcode `s3>0x0D`, 14-byte credential validate (`0x12d4`), then config worker `0xa39a`. Correlated. |

The `0xF0` config worker `0xa39a` dispatches on `payload[0]` (1..7) through a
7-entry self-relative jump table at `0x115bc`. The sub-handlers are decoded in
[analysis/config_worker.json](analysis/config_worker.json): selector 1 commits
config and sets an enable flag; 2 clears two config bytes and acks; 3 and 6 are
reserved no-ops; 4 applies a config record (`0x8dec`); **5 and 7 are bond-table
operations** that iterate the paired-peer array at `gp+0x7c` (stride `0x2B` = 43
bytes, up to index `0x81`), comparing 6-byte BLE MAC keys via resident `memcmp`
slot `0x40000040`. This is the same bond array consulted during HID name binding
(section 10), and the persistence path uses resident slots `0x40000068`/`0x4000017c`.

## 11. Recovered Function Inventory

`tools/functions.py` recovers a call graph from direct-call (`jal`) evidence and
prologue detection: **419** candidate functions in the runtime image, **84** in
boot. `analysis/functions.json` records each function's start, estimated extent,
direct callees, and caller count. The hottest utilities (by caller count) are:

| Function | Callers | Likely role |
|---:|---:|---|
| `0x110a` | 33 | Async BLE TX framer/enqueue (section 5a) |
| `0x1096` | 20 | Reply/format helper |
| `0xe310` | 11 | Shortcut rule engine (section 7) |
| `0xb86e` | 8 | Telemetry producer |
| `0xb968` | 8 | TX completion/queue worker |

This inventory is a heuristic aid (it favors precision from direct calls over an
exhaustive CFG), but it is sufficient to navigate the image and to seed a
labeled import into Ghidra/Binary Ninja.

`tools/gen_symbols.py` merges this inventory with every other artifact (command
handlers, action workers, telemetry getters, CAN decoders, rule engine, internal
commands, config worker) into a single consolidated symbol map:
[analysis/symbols.json](analysis/symbols.json) and an import-ready
[analysis/symbols.ghidra](analysis/symbols.ghidra) for Ghidra's
`ImportSymbolsScript.py` (474 entries, 86 with recovered semantic names). This is
the fastest way to bring a labeled view of the image into a disassembler.

## 12. Open Items for a Full Rewrite

- Recover the resident BLE-stack/bootloader region (physical flash dump). The
  vtable at `0x40000000` (section 5a, plus slots `0x48`/`0x3c` used by `0xD2`
  and HID binding) defines the interface to recover.
- Confirm action 139's tick period and the vehicle-side effect of the periodic
  release at `0x3ce0`.
- Generalize the periodic-task scheduler (now located) into a non-blocking macro
  executor.
- Confirm the per-vehicle meaning of each decoded CAN ID (section 10b) against a
  real harness; current labels are correlated to community Model 3/Y bus IDs.
- Confirm the semantics of each rule-engine event code (section 7) against
  vehicle behavior; the code set and source decoders are now recovered.
- Determine flash layout, image validation, and boot-slot selection.
- Resolve the `0xD2` resident diagnostic source (`0x40000048`) to a concrete
  register/sensor (the `0xF0` config worker `0xa39a` and its bond table are now
  decoded in `analysis/config_worker.json`).

See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the chronological
evidence trail and [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) for the rewrite
compatibility contract.
