# Offline Firmware Reverse Engineering Notes

Date: 2026-06-12

Artifacts analyzed:

- `latest-tsl6-535C62E239E339E31475FB10/boot/boot.bin`
- `latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin`

This analysis is offline only. No modified firmware was produced and no
firmware/update BLE commands were sent to the module.

## High-Confidence Findings

### Architecture

The firmware is RISC-V, not ARM/Cortex-M.

Evidence:

- Dense RISC-V instruction encodings such as `jal` ending in opcode `0x6f`,
  `addi` ending in opcode `0x13`, and system/CSR instructions ending in
  opcode `0x73`.
- Frequent 16-bit compressed RISC-V instructions (`c.addi`, `c.swsp`,
  `c.jr`, `c.jalr`, etc.).
- ASCII string `CH32V20x_BLE_LIB_V1.3`, which points to WCH CH32V20x BLE
  library code. CH32V parts use WCH's RISC-V QingKe cores.

### Images

Downloaded sizes:

| Image | Transport bytes | Payload bytes | Pages | Transport SHA-256 |
|---|---:|---:|---:|---|
| boot | 12,312 | 12,288 | 12 | `af8d613097164f0be2f37ca3aaf7f79d5eaa81dbf6996b0890827bd004914db7` |
| runtime | 73,872 | 73,728 | 72 | `b1b2a3aa5e71d88336719bccb5da822faffc05acf50b5b482e570f1981dabbd5` |

The downloaded files are transport streams containing 1026-byte pages. Every
page starts with a two-byte big-endian page index followed by 1024 bytes of
firmware payload. Removing those page indices produces contiguous executable
images.

Stripped-payload SHA-256:

- boot: `068c0a748ec58834258411126c610658e8008d75b88304737469a4a921f467a3`
- runtime: `7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd`

The runtime payload begins with a jump to `0xF89A`. The boot payload begins
with a jump to `0x1C28`. Executable support code begins around `0x180`.

The runtime jump/vector table contains many function-like addresses in the
`0x000178xx` range, which are inside the runtime file. That suggests the server
firmware blob is linked as an image starting at address `0x00000000` or uses
relative/bootloader-remapped addressing, rather than being directly linked at
the final flash offset in the downloaded representation.

### Identifying Strings

Runtime notable strings:

- `TSL6`
- `1234`
- `CH32V20x_BLE_LIB_V1.3`
- BLE keyboard/remote names such as `KRemote`, `BT KeyBoard`, `MINI_KEYBOARD`

Boot notable strings:

- `TSL6-BOOT`
- `CH32V20x_BLE_LIB_V1.3`

The default BLE password string `1234` appears in runtime.

## Update Protocol In Firmware

The runtime disassembly includes immediate values matching updater command
codes from the Mini App:

- `0x53` at payload offset around `0x1bd6`
- `0x45` at payload offset around `0x1be4`

These align with the Mini App updater:

- `0x55`: prepare update
- `0x53`: start selected update target
- `0x57`: write page
- `0x52`: read/verify page
- `0x45`: finalize/update version

This supports the earlier safety conclusion: readback command `0x52` is part of
the update flow, not a standalone safe full-firmware backup mechanism.

## Command/Feature Areas

The runtime image contains a large BLE command dispatcher beginning around
payload offset `0xBDEA`. It performs ordered comparisons against command bytes
and branches to command-specific handlers.

Confirmed paths include:

- `0xA0`: normal module status/info command. The main dispatcher compares
  against `0xA0` around `0xBE36`.
- `0xAB`: shortcut table command. The main dispatcher compares against `0xAB`
  around `0xBFCA`. The read path requires a one-byte payload equal to `2`,
  matching the Mini App request `tx(171, new Uint8Array([2]))`.
- `0xB0`: dashboard/gauge telemetry. A receive path around `0x9740` first
  checks that packet byte zero is `0xB0`, then validates a packet field and
  processes repeated telemetry records.
- `0xBB`: execute/test shortcut action. The dispatcher compares against `0xBB`
  around `0xC02C` and consumes the first payload byte.
- `0xC1`: vehicle type command. The dispatcher compares against `0xC1` around
  payload `0xC050`.

The dispatcher also contains explicit branches for `0xA1` through `0xA9`,
`0xAD` through `0xAF`, `0xB9`, `0xBA`, `0xC0`, `0xD0` through `0xD2`, and
other internal commands.

### Shortcut Rule Engine

The autonomous shortcut rule engine is visible around payload offset `0xE310`.
Its behavior is:

1. Load a pointer to the shortcut table.
2. Iterate from offset `0` to `0xFE` in increments of two.
3. Compare byte `N` to the incoming trigger value.
4. When it matches, load byte `N + 1`.
5. Call the action dispatcher with that single action byte.

This directly confirms the Mini App's documented 256-byte format:

```text
trigger action trigger action ...
```

The loop limit of `0xFE` means the table contains 127 usable trigger/action
pairs, with the final two bytes outside the editor's normal pair loop.

There is no delay field, step count, branch target, or pointer in a stored rule.
The firmware receives exactly one action byte from each matched rule.

Therefore a rule such as:

```text
wait 0.5 s
left scroll hold
wait 0.5 s
left scroll select
```

cannot be represented in the existing `0xAB` rule table. It can be implemented
while the Android app is connected and active by sequencing commands in the
app. Autonomous execution after the phone disconnects would require a firmware
change or reuse of an existing single action that already performs that entire
sequence internally.

### Action Dispatch

The rule engine passes the action byte into a separate dispatcher near payload
offset `0xD16E`. That dispatcher uses a jump table and contains a large set of
single-action branches.

The dispatcher performs the following operations:

1. Subtract one from the action byte.
2. Reject values above `0xFC`.
3. Multiply the result by four.
4. Load a signed 32-bit relative target from a jump table.
5. Jump to the selected action handler.

The live backend catalog currently identifies the relevant action IDs as:

| Action | Backend label |
|---:|---|
| 137 | AP speed +5 |
| 138 | AP speed -5 |
| 139 | Left scroll middle-button hold |
| 140 | Play/pause |
| 141 | Volume +1 |
| 142 | Volume -1 |
| 143 | Previous track |
| 144 | Next track |
| 145 | Voice assistant |
| 146 | AP speed +1 |
| 147 | AP speed -1 |
| 148 | Following distance +1 |
| 149 | Following distance -1 |

This catalog contains separate trigger and action namespaces. For example,
trigger 139 means speed 5-10, while action 139 means left scroll hold. Tools
must retain that distinction rather than using one global ID-to-name map.

#### Corrected action jump table

The table-base sequence at payload `0xD1E0` is:

```text
auipc a4, 4
addi  a4, a4, 0x530
```

Using standard RISC-V `AUIPC` semantics gives table base `0x11710`. The earlier
apparent alignment problem was caused by disassembling the 1026-byte
transport-page stream without removing each page's two-byte index.

Corrected selected handlers:

| Action | Payload handler |
|---:|---:|
| 137 | `0xDB54` |
| 138 | `0xDB64` |
| 139 | `0xDB74` |
| 140 | `0xDB82` |
| 141 | `0xDB92` |
| 142 | `0xDBA2` |
| 143 | `0xDBB2` |
| 144 | `0xDBC2` |
| 145 | `0xDBD2` |

Action 139 restores the dispatcher frame and tail-calls a shared routine at
payload `0x3A30`. That routine writes value `0x0C` to a RAM state byte and
returns. This is consistent with scheduling or latching a steering-wheel
operation, but the later consumer of that state byte still needs tracing.

#### Command `0xA2`

The main BLE dispatcher handles command `0xA2` around payload `0xC53C`. It accepts
payload values 1-5, calls an internal routine, and replies with command
`0xA2`. This matches the Mini App's momentary button-input behavior at a broad
level. The exact meaning of each payload value and whether the internal
routine exposes independent press/release primitives still require tracing.

Command `0xBB` is the better-established test path for stored actions: it
loads one payload byte and calls the action dispatcher near payload `0xD16E`.

### Custom Firmware Action Feasibility

The requested autonomous sequence:

```text
wait 0.5 s
left scroll hold
wait 0.5 s
left scroll select
```

cannot be stored directly in a rule. A firmware implementation would likely
need all of the following:

1. Choose an unused or deliberately repurposed action ID.
2. Repoint that jump-table entry to injected code.
3. Call the confirmed left-scroll hold primitive.
4. Schedule a non-blocking 500 ms delay.
5. Call a confirmed release/select primitive.
6. Preserve registers, stack, watchdog servicing, BLE timing, and CAN task
   timing expected by the original firmware.

A blocking busy-wait is not acceptable without proving the scheduler and
watchdog behavior. A safe implementation probably needs the firmware's own
timer/work-queue mechanism, which has not yet been identified.

There is now enough understanding to describe a credible patch architecture,
but not enough to produce firmware that is safe to flash. The current blockers
are:

- Resolve the action jump-table alignment/control-flow discrepancy.
- Confirm action 139 by observing or tracing its actual vehicle-side effect.
- Identify separate press, release, and select primitives.
- Identify a non-blocking timer primitive and its calling convention.
- Find verified executable free space or a relocatable code region.
- Determine all image checksum, version, signature, and bootloader validation
  requirements.
- Establish hardware recovery using a full physical flash dump and WCH-Link,
  preferably with a spare module for first tests.

Other application areas contain clustered constants such as:

- `0x41` through `0x4f`, `0x5e`, `0x5f`, `0x6a` through `0x6d`, `0x96`, `0x97`,
  and similar action-like constants appear in clustered control logic.
- Several regions manipulate byte fields at fixed offsets within packet-like
  structures, consistent with command payload parsing and vehicle action
  dispatch.

### Update Dispatcher

A separate updater dispatcher is visible around payload offset `0xBC76`. It
explicitly accepts `0x45`, `0x53`, `0x55`, and `0x57`, while another update
path selects `0x52` or `0x57` based on state. This further supports treating
`0x52` as an update-flow read/verify operation rather than a safe normal-mode
full-flash backup API.

## Why Confident Modification Is Not Ready

The current analysis identifies architecture and broad regions, but it is not
enough to safely modify behavior.

Missing pieces:

- Exact chip variant and flash/RAM map.
- Exact payload-to-flash mapping.
- Reset/boot vectors after bootloader remapping.
- Symbol recovery for BLE stack vs application code.
- Action-handler side effects and low-level button primitives.
- The consumer and timing semantics of the RAM action-state byte written by
  the action 139 routine.
- Whether images have hidden signatures, version checks, or post-download
  integrity constraints beyond the server page checksums.
- A hardware recovery path, such as SWD/WCH-Link access and a full physical
  flash dump.

Because the hardware is vehicle-adjacent and because update-mode semantics are
not fully proven, patching and flashing modified firmware to a working TSL6 is
not recommended.

## Useful Local Analysis Files

Generated offline alongside the archived images. Not all generated files are
committed because full disassembly output is noisy.

Useful generated files:

- `boot/boot.analysis.json`
- `boot/boot.disasm.txt`
- `runtime/runtime.analysis.json`
- `runtime/runtime.base0.analysis.json`
- `runtime/runtime.base0.seeded.disasm.txt`
- `runtime/runtime.seeded.disasm.txt`

Tooling is maintained in the Android repository
([TSL-Cmd](https://github.com/jfryton/TSL-Cmd), `tools/analyze_firmware.py`).

It uses Capstone in a local virtual environment to disassemble RISC-V/RVC.
It can also emit a targeted disassembly window:

```sh
tools/.venv-re/bin/python tools/analyze_firmware.py \
  /path/to/runtime.bin --base 0 --start 0xBE40 --count 120
```

The JSON report now includes decoded instruction-immediate hits for known
protocol command values. Raw byte hits alone are noisy because command values
also occur inside unrelated instruction encodings and data.

## Suggested Next Steps

1. Confirm exact MCU marking on the TSL6 PCB.
2. Obtain or create a physical full-flash dump with WCH-Link/SWD before any
   firmware experimentation.
3. Import the runtime image into Ghidra using RISC-V 32-bit little-endian with
   compressed instructions enabled.
4. Use the known strings and updater command constants to label functions.
5. Label each `0xAB` read/write branch and identify the exact nonvolatile
   storage routines used for the 256-byte rule table.
6. Map action IDs from the backend catalog to branches in the action jump table.
7. Determine whether any existing action already performs a multi-step
   hold/select sequence internally.
8. Only after full recovery capability exists, consider testing a non-critical
   proof-of-concept patch on spare hardware.
