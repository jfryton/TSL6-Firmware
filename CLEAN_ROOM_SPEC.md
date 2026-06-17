# TSL6 Clean-Room Firmware Compatibility Specification

Status: work in progress  
Updated: 2026-06-12

This document records behavior needed to build an independently implemented
TSL6-compatible firmware. It does not authorize flashing a production module
and does not claim that the bootloader or vehicle CAN protocol is fully known.

Confidence labels:

- **Confirmed**: directly present in recovered application code or disassembly.
- **Correlated**: independent sources agree, but vehicle-side behavior has not
  been measured.
- **Inferred**: likely interpretation that still needs hardware validation.
- **Unknown**: required for a replacement but not yet recovered.

## 1. Hardware and Execution Environment

| Item | Status | Finding |
|---|---|---|
| CPU family | Confirmed | WCH CH32V20x-compatible QingKe RISC-V core |
| ISA | Confirmed | RV32 with compressed RVC instructions |
| BLE library | Confirmed | `CH32V20x_BLE_LIB_V1.3` |
| Endianness | Confirmed | Little-endian executable data |
| Runtime payload | Confirmed | 73,728 bytes, exactly 72 KiB |
| Boot payload | Confirmed | 12,288 bytes, exactly 12 KiB |
| Runtime reset jump | Confirmed | Payload offset `0x0000` jumps to `0xF89A` |
| Boot reset jump | Confirmed | Payload offset `0x0000` jumps to `0x1C28` |
| Exact MCU part | Unknown | PCB marking or debug ID required |
| Oscillator and clock tree | Unknown | Must be measured or recovered |
| GPIO/CAN transceiver mapping | Unknown | Requires PCB tracing or live probing |

The binaries contain direct references into the standard CH32V peripheral
region around `0x40000000` and RAM references around `0x20000000`.

## 2. Server Transport Versus Flash Payload

The vendor server does not return a raw flash image. It returns 1026-byte
transport pages:

```text
byte 0: page index high byte
byte 1: page index low byte
bytes 2-1025: 1024-byte executable payload
```

Each complete page is covered by a server-provided 16-bit additive checksum:

```text
checksum = sum(all 1026 page bytes) mod 65536
```

Removing the two-byte index from every page produces:

| Image | Transport | Pages | Payload |
|---|---:|---:|---:|
| runtime | 73,872 bytes | 72 | 73,728 bytes |
| boot | 12,312 bytes | 12 | 12,288 bytes |

Transport offset conversion for bytes after a page header:

```text
page = transport_offset // 1026
within_page = transport_offset % 1026
payload_offset = page * 1024 + within_page - 2
```

Offsets `0` and `1` of each transport page are not executable payload.

All firmware offsets in this specification refer to the stripped payload
unless explicitly labeled `transport`.

## 3. BLE Service and Packet Framing

### GATT

| Item | Value | Status |
|---|---|---|
| Service UUID | `FFF0` | Confirmed |
| Command/notify characteristic | `FFF1` | Confirmed |
| Requested Android MTU | 247 | Confirmed |
| Maximum application chunk | 244 bytes | Confirmed |

The same `FFF1` characteristic is selected when it supports notification and
one of write, write-default, or write-without-response.

### Application Frame

```text
offset  size  field
0       1     0x55
1       1     0x7F
2       1     command/type
3       1     payload length high byte
4       1     payload length low byte
5       N     payload
5+N     1     checksum
```

Checksum:

```text
sum(command, length high, length low, every payload byte) mod 256
```

Frames may be split across BLE writes/notifications. The receiver resets its
parser if at least 500 ms passes between received chunks. Maximum accepted
payload length in the recovered Mini App parser is 4096 bytes.

## 4. Firmware Update Transport

| Command | Purpose | Status |
|---:|---|---|
| `0x55` | Prepare/select update target | Confirmed |
| `0x53` | Begin selected target update | Confirmed |
| `0x57` | Write one 1026-byte transport page | Confirmed |
| `0x52` | Read one transport page for verification | Confirmed |
| `0x45` | Finalize and report completion | Confirmed |

Prepare payload:

```text
target: 1 byte, 0 = boot, 1 = runtime
UID:    14 bytes
```

Start payload:

```text
target: 1 byte
UID:    14 bytes
```

Write payload is one complete server page, including its two-byte big-endian
page index. Read payload is:

```text
page index high
page index low
14-byte UID
```

Finalize payload:

```text
target: 1 byte
14-byte UID
```

The Mini App retries writes every 1200 ms, with a maximum of ten attempts. It
retries reads every 1000 ms, with a maximum of five attempts.

**Unknown and safety-critical:**

- Actual flash destination for boot and runtime payloads.
- Erase granularity and atomicity.
- Boot-selection flags and rollback behavior.
- Bootloader image validation beyond page transport checks.
- Whether a failed runtime update leaves a recoverable bootloader.
- Whether bootloader replacement can remove the only BLE recovery route.

The updater protocol alone is not a safe firmware-backup protocol. A clean-room
firmware project must first obtain a physical flash dump and debug recovery.

## 5. Normal Command Surface

The runtime's main BLE command dispatcher starts near payload `0xBDEA`.

| Command | Observed purpose | Status |
|---:|---|---|
| `0xA0` | Module status/device information | Confirmed |
| `0xA1` | Primary setting/control family | Correlated |
| `0xA2` | Momentary steering-wheel button input, values 1-5 | Correlated |
| `0xA5` | Module reboot | Confirmed by Mini App |
| `0xA7` | Vehicle quick-control family | Correlated |
| `0xA8` | Four-character BLE password verification | Confirmed |
| `0xA9` | BLE password change | Confirmed by Mini App |
| `0xAB` | 256-byte trigger/action shortcut table | Confirmed |
| `0xAD` | Factory reset/authorization family | Confirmed by Mini App |
| `0xAE` | Authorization-state transition | Confirmed by Mini App |
| `0xAF` | Activation token | Confirmed by Mini App |
| `0xB0` | Dashboard telemetry enable/data | Confirmed |
| `0xB9` | RGB/ambient-light configuration | Confirmed |
| `0xBA` | BLE-button configuration | Confirmed |
| `0xBB` | Execute/test one shortcut action | Confirmed |
| `0xC0` | CAN debug transport | Confirmed |
| `0xC1` | Vehicle type query | Confirmed |

The complete payload schemas for several commands remain incomplete. They
should be captured as versioned structures rather than duplicated ad hoc.

## 6. Shortcut Rule Storage

The rule engine begins near payload `0xE310`.

The first rule table is 256 bytes:

```text
trigger_0 action_0 trigger_1 action_1 ... trigger_126 action_126
```

The scan:

1. Starts at offset zero.
2. Compares the first byte of each pair to the incoming trigger.
3. Calls the action dispatcher using the second byte.
4. Advances by two bytes.
5. Stops before offset `0xFE`.

This gives 127 trigger/action pairs. No delay, sequence count, pointer, or
macro bytecode exists in this table.

The same function also scans two additional structures:

- Each has entries spaced seven bytes apart.
- Each exposes 36 logical positions.
- A 9-bit trigger value is assembled from an entry's first two bytes.
- Bit 1 of the second byte controls whether an associated operation executes.

These structures likely correspond to other configurable quick-control or
RGB/button tables, but their full schema is not yet confirmed.

## 7. Action Dispatcher

The action dispatcher begins at payload `0xD16E`.

Dispatch algorithm:

```text
index = (action_id - 1) & 0xFF
if index > 0xFC:
    reject
target = table_base + signed_le32(table_base + index * 4)
jump target
```

The corrected payload table base is `0x11710`. Removing server page headers
resolves the earlier apparent handler-alignment contradiction.

Selected confirmed table targets:

| Action | Catalog meaning | Handler |
|---:|---|---:|
| 137 | AP speed +5 | `0xDB54` |
| 138 | AP speed -5 | `0xDB64` |
| 139 | Left scroll middle-button hold | `0xDB74` |
| 140 | Play/pause | `0xDB82` |
| 141 | Volume +1 | `0xDB92` |
| 142 | Volume -1 | `0xDBA2` |
| 143 | Previous track | `0xDBB2` |
| 144 | Next track | `0xDBC2` |
| 145 | Voice assistant | `0xDBD2` |
| 146 | AP speed +1 | `0xDBF2` |
| 147 | AP speed -1 | `0xDC02` |
| 148 | Following distance +1 | `0xDC12` |
| 149 | Following distance -1 | `0xDC22` |

Action 139's stub restores the dispatcher frame and tail-calls a shared
routine without loading an immediate parameter. This distinguishes it from
neighboring parameterized media and AP actions, but its complete CAN-side
behavior still needs live correlation.

Trigger IDs and action IDs are separate namespaces. Trigger 139 means speed
5-10; action 139 means left-scroll hold.

## 8. Dashboard Telemetry Contract

The Mini App requests dashboard data using command `0xB0`, payload `[1]`, once
per second. Payload `[0]` disables dashboard mode.

The returned payload is at least 33 bytes and includes:

| Bytes/bits | Meaning |
|---|---|
| 0-3 bits 0-8 | Speed |
| 0-3 bits 9-11 | Gear |
| 0-3 bits 12-13 | Turn signals |
| 0-3 bits 14-15 | Autopilot state |
| 0-3 bits 16-19 | Door state |
| 0-3 bits 20-24/27 | Lighting/brake indicators |
| 0-3 bits 24-30 | State of charge |
| 4-7 bit 0 | Keep-screen-on hint |
| 4-7 bit 2 | Vehicle light/dark appearance |
| 4-7 bit 3 | Sport mode |
| 4-7 bits 6-31 | Odometer, 0.1 km |
| 8-11 | Four tire pressures, raw * 0.025 |
| 12-15 bits 0-7 | Accelerator pedal, raw/250 |
| 12-15 bits 8-18 | Rear inverter power, signed /2 |
| 12-15 bits 19-29 | Front inverter power, signed /2 |
| 15-17 bits 6-19 | Altitude, signed meters |
| 17 bits 4-5 | Battery heating state |
| 17 bit 6 | Speed units |
| 17 bit 7 | Hands-on reminder |
| 18-22 | Four brake temperatures, encoded value -40 |
| 23-26 bits 0-9 | HVAC blower RPM, raw * 5 |
| 23-26 bits 10-20 | Evaporator demand watts, raw * 5 |
| 23-26 bits 21-31 | Cabin estimate, raw * 0.1 -40 |
| 27 | Ambient temperature, raw * 0.5 -40 |
| 28-31 bits 0-11 | Cell voltage, raw * 0.002 V |
| 28-31 bits 12-21 | Remaining range, raw * 1.61 km |
| 28-31 bits 22-30 | Battery temperature, raw * 0.5 -40 |
| 31-32 bits 7-11 | Fused speed limit, raw * 5 |
| 31-32 bits 12-15 | Rear blind-spot states |

This is sufficient to reproduce the original dashboard-facing BLE contract.
It is not sufficient to reproduce how those values are extracted from each
supported Tesla CAN generation.

## 9. Replacement Firmware Architecture

A clean-room implementation should keep these concerns separate:

1. Boot and recovery layer.
2. BLE GATT transport and frame parser.
3. Versioned command schemas.
4. Persistent configuration with CRC and dual-copy recovery.
5. Vehicle-profile-specific CAN decoders.
6. Validated action executor with explicit safety gates.
7. Non-blocking macro scheduler.
8. Telemetry snapshot producer.
9. Watchdog and fault recorder.

For custom macros, use a versioned bytecode or structured record instead of
overloading the original two-byte rules. Minimum operations:

```text
PRESS(button)
RELEASE(button)
SELECT(button)
WAIT_MS(duration)
ACTION(existing_action_id)
END
```

Execution must be non-blocking. Every macro should have:

- Maximum step count.
- Maximum total duration.
- Cancellation on invalid gear/state or CAN timeout.
- Watchdog-friendly scheduling.
- No dynamic allocation in the real-time path.
- Persistent schema version and CRC.

## 10. Required Work Before Replacement Firmware

### Hardware recovery

- Identify the exact CH32V part from package marking or debug ID.
- Trace SWD/WCH-Link pads and voltage levels.
- Capture a full physical flash dump, option bytes, and device configuration.
- Verify that a known-good image can be restored before any experimental boot.
- Use a spare module for first execution.

### Boot validation

- Recover flash layout and linker origins.
- Determine vector relocation and runtime image destination.
- Determine boot flags, update-in-progress markers, and rollback behavior.
- Identify all CRC/signature/version checks.
- Document brownout behavior during erase/write.

### Vehicle compatibility

- Inventory every supported hardware/vehicle profile.
- Capture passive CAN traces only, with timestamps and bus identification.
- Map signal extraction separately for each profile.
- Confirm wake/sleep behavior and current consumption.
- Confirm that bus transmission stops on CAN errors, stale state, or watchdog
  recovery.

### Verification gates

- Host tests for BLE framing and every command schema.
- Golden-vector tests for dashboard payloads and persistent storage.
- Fuzz tests for malformed BLE frames.
- Hardware-in-loop testing without a vehicle before CAN transmission.
- Current-consumption and sleep/wake testing.
- Power-loss tests during configuration writes and firmware updates.
- Long-duration watchdog, BLE reconnect, and CAN bus-off tests.

Until these are complete, a replacement firmware can be prototyped but cannot
reasonably be described as non-bricking or production-safe.
