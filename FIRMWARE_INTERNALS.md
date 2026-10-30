# TSL6 Firmware Internals

Component-level documentation of the TSL6 runtime and boot firmware, derived by
static analysis of the archived images. The goal is a complete enough picture to
understand, edit, and eventually rewrite the firmware now that the original
project is abandoned.

All code addresses in this document are **payload offsets** (stripped image,
base 0), unless explicitly labelled `linked`, `flash alias`, or `transport`.
See
[ANALYSIS_WORKFLOW.md](ANALYSIS_WORKFLOW.md) for how payload images are produced
from the downloaded transport pages, and [tools/](tools/) for the reproducible
analyzer used here.

Machine-readable companions to this document live in [analysis/](analysis/):

- `memory_map.json` - linker constants and region model
- `command_dispatch.json` - every BLE command and its handler offset, plus the
  shared reply/TX helpers and resident ABI slots
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
| Runtime linked/flash bases | `0x00008000` / `0x08008000` | Confirmed |
| Boot linked/flash bases | `0x00001000` / `0x08001000` | Confirmed |
| Accepted runtime/boot slots | `0x18000` / `0x7000` bytes | Confirmed |

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
| Runtime linked code base | `0x00008000` | base required for AUIPC address resolution |
| Runtime flash alias | `0x08008000` | destination used by the boot updater |
| `gp` (global pointer) | `0x20004000` | base for `gp`-relative state block |
| `sp` (stack pointer) | `0x20010000` | top of stack/RAM |
| RAM base | `0x20000000` | CH32V20x SRAM |
| Resident BLE library base | `0x00040000` | out-of-image library image |
| Resident jump-table base | `0x00040034` | function-pointer table within that library |
| Peripheral base | `0x40000000` | CH32V20x peripherals |

Startup performs the standard C runtime bring-up:

1. Copy `.data` from flash to RAM (`gp .. gp+0xa8`).
2. Zero `.bss` (`gp+0xa8 .. 0x2000c970`).
3. Program CSRs: `0xbc0=0x1f`, `0x804=3`, set `mstatus`, set `mtvec` (vectored,
   mode 3), then `mret` into the application via `mepc`.

The boot image uses the same pattern with linked base `0x00001000`, flash alias
`0x08001000`, `gp=0x20004000`, `sp=0x20010000`, and reset jump
`0x0000 -> 0x1c28`.

### Resident vs. updatable code

The downloadable runtime image contains application code at payload offsets
`0x0..0x11fff`, linked at `0x00008000`. Startup and indirect calls also target a
resident BLE library around `0x00040000` and its jump table at `0x00040034`,
which the downloaded image does not
contain. This low address must not be confused with the CH32V peripheral region
at `0x40000000`. Practically:

- The server `isapp=1` image is the **application/runtime slot** only.
- Resident BLE-library code referenced during startup is **not** in this image
  and must be recovered separately (physical flash dump) before a full rewrite.
  Which hardware services also live there remains Unknown.
- The mechanism that maps flash aliases to the low linked/execution views, and
  the storage backing `0x00040000`, remain Unknown.

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
| `0xD0` | `0xc060` | Enable/select notification stream | Confirmed |
| `0xD1` | `0xc2da` | Disable notification stream | Confirmed |
| `0xD2` | `0xc08c` | Return an 8-byte view of raw record slot 4 | Confirmed structure |
| `0xF0` | `0xc0ee` | Configuration/provisioning family | Correlated |

The `0xA0` handler reply builder also dispatches sub-commands `0xAD`, `0xAE`,
`0xA8` (factory/authorization/password-verify) seen at `0xbcc8..`.

### Handler details (confirmed by disassembly)

- **`0xA1`** (`0xbe7c`): validates via `0x1a6`, then emits a `0x12c`-byte (300)
  reply through BLE frame builder/enqueue `0x0d02` - a bulk settings/state
  dump.
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
keycode into a RAM state byte at `0x2000bf2c` (`auipc a5,0x20001; sb s0,
-0x4e0(a5)`). This single
primitive is reused by most of the media/AP/steering action handlers (section
6), which is why those actions are parameterized tail-calls rather than distinct
code.

## 5a. BLE Transmit, Scheduling, and Resident ABI

Outbound BLE frames and delayed work use these shared helpers (Confirmed):

| Helper | Role |
|---:|---|
| `0x0d02` | BLE frame builder/enqueue. Emits the `55 7F` header and checksum, then requests resident event-loop work. |
| `0x110a` | 15-slot delayed-callback scheduler. Its 12-byte entries begin at RAM `0x2000be28`; delay values in milliseconds are converted to 625-us ticks. |
| `0xb76c` | Generic command reply builder. Uses `tmos_msg_allocate` at `0x40070`, `tmos_memcpy` at `0x4004c`, `0x0d02`, then `tmos_msg_deallocate` at `0x40068`. |
| `0xb7c6` | Module status reply builder (used by `0xA0`, `0xB0`). |
| `0xb86e` | Dashboard telemetry producer; emits the 35-byte `0xB0` packet, rate-limited using a timestamp at `gp+0x178`. |
| `0xbdb8` | Reply tail shared by the `0xA2`/`0xBB` handlers. |

These helpers use the resident BLE library at `0x00040000` and its
**ABI/function-pointer jump table** at `0x00040034`. Both images embed the
version string `CH32V20x_BLE_LIB_V1.3`. OpenWCH header
`EVT/EXAM/BLE/LIB/wchble_rom.h` at commit
`64be9554615df522899579633530fd234d685682` defines those exact bases and the
slot names below; the firmware's indirect-call shapes agree.

| Slot | Use |
|---|---|
| `0x4003c` | `tmos_memcmp(src1, src2, len)`; returns `TRUE` when equal. |
| `0x40040` | `tmos_isbufset(buf, value, len)`; returns `TRUE` when all bytes equal `value`. |
| `0x40048` | `tmos_memset(dst, value, len)`. |
| `0x4004c` | `tmos_memcpy(dst, src, len)`. |
| `0x40050` | `tmos_set_event(task_id, event)`. |
| `0x40068` | `tmos_msg_deallocate(msg_ptr)`. |
| `0x40070` | `tmos_msg_allocate(len)`. |
| `0x4017c` | `GAPRole_TerminateLink(conn_handle)`. |

The table proves a resident software ABI outside the downloaded image. It does
not by itself identify the table's physical flash backing or every slot's
subsystem. The actual peripheral region remains `0x40000000` (section 2).

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
  `0x2000bf2d`. Branch `0x3cdc` reads the counter; whenever it is nonzero, it
  decrements it and replaces bits 6:5 of the current object's byte 3 with
  `0b10`. The call cadence, why value 12 is chosen, and the resulting
  vehicle-side hold/release semantics remain unproven.

Trigger IDs and action IDs are **separate namespaces**. The backend catalogs
trigger 139 as "speed 5-10" and action 139 as "left scroll hold"; these labels
do not prove vehicle-side effects. Tools must not share one label map.

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

The two downloaded images contain complementary local flash writers
(Confirmed):

| Running image / worker | Accepted start target | Destination | Accepted pages |
|---|---:|---:|---:|
| Runtime `0x1bc8` | `0` (boot) | `0x08001000` | `0..27` (`0x7000` bytes) |
| Boot `0x121c` | `1` (runtime) | `0x08008000` | `0..95` (`0x18000` bytes) |

Both workers require a `0x402`-byte transport page, perform four 256-byte fast
erase/program cycles for its 1 KiB payload, and verify the result word-by-word.
Both access the CH32V flash controller at `0x40022000` through helpers local to
their own image: boot `0x2032`/`0x203a`/`0x2058`/`0x2066`/`0x2094`, and runtime
copies `0x10010`/`0x10018`/`0x10036`/`0x10044`/`0x10072`.

Their wrapper temporarily changes RCC `CFGR0` at `0x40021004`: comparison with
144 MHz selects HPRE divide-by-2 (`0x80`) or divide-by-4 (`0x90`). That address
is not flash control. The flash routines poll busy state with no timeout, do not
test flash error/completion bits, and return no status. Runtime prepare target
`1` schedules callbacks `0xe1a` after 200 ms and `0x1e16` after 400 ms through
`0x110a`, transferring toward the boot-mode runtime writer.

The complete static flow is documented in [BOOTLOADER.md](BOOTLOADER.md) and
the generated runtime/boot analysis JSON.

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

The packed bytes are assembled by the telemetry packer at **`0xb3e0`**. It first
zeroes its stack output buffer through `tmos_memset` at `0x40048`, then reads
the live vehicle state from the CAN-decoded RAM cache
(including gear at `0x2000bf60`) and builds the packet word-by-word.
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
list using `tmos_memcmp` (loaded from slot `0x4003c` / `lw a5,0(s6)`), passing
the candidate string pointer, the peer name, and the length. This ABI returns
`TRUE` for equality: zero advances to the next candidate, while nonzero selects
the matching profile. Confirmed comparisons:

| Name string | Offset | Length | Compare site |
|---|---|---:|---|
| `BT KeyBoard` | `0x11604` | 11 | `0x99ce` |
| `MINI_KEYBOARD` | `0x11620` | 13 | `0x9a54` |
| `BLE-M3` | `0x11630` | 6 | `0x9a6c` |

Full decode in [analysis/internal_commands.json](analysis/internal_commands.json)
(`hid_name_binding`).

## 10a. gp-Relative State Block

All mutable BLE/rule/connection state lives in a single block based at the global
pointer (`gp=0x20004000`). `tools/map_state.py` sweeps the whole image and
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
signal cache** (telemetry landmarks around `0x2000be5c`-`0x2000bf86`); the dashboard getters in section 9
sample this cache. `tools/map_ramcache.py` maps it
([analysis/ram_cache.json](analysis/ram_cache.json)): 357 candidate RAM addresses,
with the 10 telemetry-sampled slots identified by getter, e.g. gear at
`0x2000bf60`, SoC at `0x2000bf81`, autopilot at `0x2000bf00`, door at
`0x2000bf86`. The broad AUIPC scan is heuristic; these ten telemetry landmarks
are checked against their getters.

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
reads frame byte 5, shifts right 5 (top 3 bits), stores to `0x2000bf60`, and on
change increments the `gp+0x108` dirty counter.

## 10c. Internal Commands (D0 / D1 / D2 / F0)

Beyond the action and telemetry commands, four control commands cover
notification streams, a raw-record reply, and provisioning-related paths. Full evidence in
[analysis/internal_commands.json](analysis/internal_commands.json).

| Cmd | Handler | Role |
|---|---|---|
| `0xD0` | `0xc060` | Enable/select a per-connection notification stream (payload[0]==1, status setter `0xb7c6` selector 3). Confirmed. |
| `0xD1` | `0xc2da` | Disable that stream (payload[0]==1, `0xb7c6` selector 4). Confirmed. |
| `0xD2` | `0xc08c` | Zero an 8-byte response buffer through `0x40048`, copy raw 12-byte record slot 4 into a separate scratch buffer through local helper `0x28e`, copy scratch bytes 3..8 into the response, and send it through `0x0d02`. Confirmed structure; record meaning Unknown. |
| `0xF0` | `0xc0ee` | Configuration/provisioning family: subcode `s3>0x0D`, 14-byte value validate (`0x12d4`), then worker `0xa39a`. Correlated. |

`0x40048` does not fetch a diagnostic source; it is `tmos_memset`, also used by
telemetry. Helper `0x28e` selects a raw-record slot, multiplies the index by 12,
and copies one 12-byte record through `tmos_memcpy` at `0x4004c`. The producer
and semantic meaning of D2 record slot 4 remain Unknown.

The `0xF0` config worker `0xa39a` dispatches on `payload[0]` (1..7) through a
7-entry self-relative jump table at `0x115bc`. The sub-handlers are decoded in
[analysis/config_worker.json](analysis/config_worker.json): selector 1 writes
`1` to two RAM bytes and calls `0x8ac0`; selector 2 clears those bytes and calls
`tmos_set_event`; selectors 3 and 6 return without work; selector 4 builds and
passes a `0x88`-byte message through `0x8dec`; and selectors 5 and 7 scan three
43-byte records whose pointer is stored at `gp+0x7c`. Their six-byte fields at
offset `+3` are tested with `tmos_isbufset` or compared with `tmos_memcmp`.
Paired-peer/bond semantics are Correlated, not proven, and the complete effects
of all selectors remain unresolved.

## 11. Recovered Function Inventory

`tools/functions.py` recovers a call graph from direct-call (`jal`) evidence and
prologue detection: **419** candidate functions in the runtime image, **84** in
boot. `analysis/functions.json` records each function's start, estimated extent,
direct callees, and caller count. The hottest utilities (by caller count) are:

| Function | Callers | Likely role |
|---:|---:|---|
| `0x110a` | 33 | Delayed-callback scheduler (section 5a) |
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
`ImportSymbolsScript.py` (474 entries, 87 with recovered semantic names). This is
the fastest way to bring a labeled view of the image into a disassembler.

## 12. Open Items for a Full Rewrite

- Recover the resident BLE-library region (physical flash dump). The jump table
  at `0x00040034` defines part of the interface to recover; its
  backing storage and relation to the low execution remap remain Unknown.
- Confirm action 139's branch cadence and vehicle-side effect; only the
  countdown write/decrement and bit replacement are currently proven.
- Confirm the per-vehicle meaning of each decoded CAN ID (section 10b) against a
  real harness; current labels are correlated to community Model 3/Y bus IDs.
- Confirm the semantics of each rule-engine event code (section 7) against
  vehicle behavior; the code set and source decoders are now recovered.
- Confirm the recovered flash aliases and slot bounds with a physical dump;
  determine image validation, remap, selection, rollback, and recovery state.
- Identify the producer and meaning of raw record slot 4 returned by `0xD2`.

See [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) for the chronological
evidence trail and [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) for the rewrite
compatibility contract.
