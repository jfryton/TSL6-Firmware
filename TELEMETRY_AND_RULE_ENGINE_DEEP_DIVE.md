# Code Context: TSL6 Firmware (`V1.5.00`) Deep Reverse Engineering — `0xB0` Telemetry, `0xAB` Rule Engine, & `TSL Cmd` Automation Architecture

## Files Retrieved
1. `/root/projects/TSL6-Firmware/work/runtime.payload.bin` (offsets `0x0000..0x11FFC`, linked at `0x00008000` / flash alias `0x08008000`, `gp = 0x20004000`) — Stripped CH583 RISC-V (`rv32imac`) runtime payload containing the BLE command dispatcher, `0xB0`/`0xD0` packet builders, CAN decoders, and the `0xAB`/`0xAE`/`0xAC` rule/shortcut engine.
2. `/root/projects/TSL6-Firmware/FIRMWARE_INTERNALS.md` (lines 1–274) — Baseline memory map, BLE command table, and CAN/telemetry architectural notes.
3. `/root/projects/TSL6-Firmware/CLEAN_ROOM_SPEC.md` (lines 1–415) — Clean-room protocol specification for `TSL Cmd`, `0xB0` telemetry layout, and `0xAB`/`0xAC`/`0xAE` rule persistence.
4. `/root/projects/TSL6-Firmware/AUTOMATIC_VOLUME.md` (lines 1–128) — Analysis of the `0x25b0` automatic volume & anti-nag periodic scheduler and `0x45a2` (`0x4672`) stalk/wiper CAN `0x249` handler.
5. `/root/projects/TSL6-Firmware/analysis/telemetry.json` (lines 1–171) — Initial `0xB0` telemetry bitfield extraction notes.
6. `/root/projects/TSL6-Firmware/analysis/rule_engine.json` (lines 1–120) & `/root/projects/TSL6-Firmware/analysis/rule_triggers.json` (lines 1–150) — Initial rule engine and trigger cross-reference data.
7. `/root/projects/TSL6-Firmware/analysis/action_table.json` (lines 1–260) — Jump table targets for `0xd16e` (`0x11710`).
8. `/root/projects/TSL6-Firmware/analysis/command_dispatch.json` (lines 1–140) & `/root/projects/TSL6-Firmware/analysis/config_worker.json` (lines 1–120) — BLE `0xA0..0xF1` command handler and flash persistence offsets.

---

## Key Code & Complete Technical Findings

### Part 1: `0xB0` Telemetry Packet Builder (`0xb3e0..0xb76c`) & CAN-Decoded RAM Cache

#### 1.1 Telemetry Producer & Framing (`0xb86e..0xb968` & `0xb3e0..0xb76c`)
- **Producer Task (`0xb86e`)**:
  - Checks `0x20004190` (`0x190(gp)`, subscription enable flag set by BLE commands `0xA0` / `0xF1`).
  - Reads the active packet mode at `0x20004191`:
    - Mode `0xB0`: calls `0xb3e0`, which allocates a stack buffer at `sp+0xc`, zeros **33 bytes (`0x21`)** via `tmos_memset` (`0x40048`), populates bytes `0..32`, and passes `(cmd=0xB0, buf=sp+0xc, len=0x21)` to the frame builder `0x0d02`.
    - Mode `0xD0`: calls `0xaf6c`, which zeros and populates a **76-byte (`0x4C`)** diagnostic/config status payload and sends `(cmd=0xD0, buf=sp+0x14, len=0x4C)` via `0x0d02`.
  - **BLE Notification Frame (`0x0d02`)**: Wraps the payload as `[0xAA, 0x55, cmd, len, ...payload..., checksum]`, where `checksum = (cmd + len + sum(payload)) & 0xFF`. Thus a `0xB0` notification over `FFF4` is **38 bytes** total (`4` header + `33` payload + `1` checksum).

#### 1.2 Complete Byte-by-Byte & Bit-by-Bit Map of the 33-Byte `0xB0` Payload (`buf[0..32]`)
Every instruction in `0xb3e0..0xb76c` and all 31 getter functions were disassembled and traced back to their RAM cache variables and CAN frame decoders:

| Payload Offset | Bits | Signal Name | Getter Fn | RAM Cache Address | CAN Source Frame & Decoder | Encoding / Formula / Notes |
|---|---|---|---|---|---|---|
| `buf[0]` | `7:0` | `speed_kmh_low` | `0x80e0` | `0x20004070` (`u16` @ `0x70(gp)`) | CAN `0x257` (`0x7f88`) | Low 8 bits of 9-bit unsigned integer speed (`0..511` km/h or mph per UI unit). |
| `buf[1]` | `0` | `speed_kmh_bit8` | `0x80e0` | `0x20004070` (`u16` @ `0x70(gp)`) | CAN `0x257` (`0x7f88`) | Bit 8 (`(speed >> 8) & 1`). Combined: `speed = buf[0] \| ((buf[1] & 1) << 8)`. |
| `buf[1]` | `3:1` | `gear` | `0x4d14` | `0x2000445e` (`u8`) | CAN `0x118` (`0x4b82`) | 3-bit gear state (`(val & 7) << 1`): `1`=Park, `2`=Reverse, `3`=Neutral, `4`=Drive. |
| `buf[1]` | `5:4` | `turn_signal` | `0x2900` | `0x200042bc` (`u8`) | CAN `0x3f5` (`0x25f6`) | 2-bit turn indicator (`(val & 3) << 4`): `0`=Off, `1`=Left, `2`=Right, `3`=Hazard/Both. |
| `buf[1]` | `6` | `autopilot_active` | `0x2d08` | `0x200042f1` (`u8`) | CAN `0x39d` / `0x2b6` (`0x2a24..0x2c60`) | `1` when Autopilot / Autosteer is active (`0x200042f1 == 2`). |
| `buf[1]` | `7` | `driver_door_open` | `0x5d42` | `0x20003fa9` (`u8`) | CAN `0x102` (`0x57d0..0x5860`) | `1` when Front-Left (driver) door is open. |
| `buf[2]` | `0` | `high_beam` | `0x28ba` | `0x200042bb` (`u8`) | CAN `0x3f5` (`0x25f6..0x28b8`) | `1` when high beams are active. |
| `buf[2]` | `1` | `battery_heater_on` | `0x51ec` | `0x200044b5` (`u8`) | CAN `0x333` / `0x312` (`0x5188..0x51ea`) | `1` when BMS battery preconditioning / heater is active. |
| `buf[2]` | `2` | `KeepClimate` / `ui_unit` | `0x7e08` | `0x20004628` (`u8`) | CAN `0x3b6` / `0x2e5` (`0x7d44..0x7e06`) | 1-bit flag stored at `0x20004628` (`(val & 1) << 2`). |
| `buf[2]` | `3` | `charge_flap_or_lock` | `0x7370` | `0x200045eb` (`u8`) | CAN `0x383` / `0x3f2` (`0x7250..0x736e`) | 1-bit status flag (`(val & 1) << 3`). |
| `buf[2]` | `4` | `frunk_open` | `0x5bd0` | `0x20003faa` (`u8`) | CAN `0x2e1` (`0x5bd8..0x5cf8`) | `1` when front trunk (frunk) is open. |
| `buf[2]` | `5` | `sport_mode` | `0x76a8` | `0x20004605` (`u8`) | CAN `0x334` / `0x3b3` (`0x755e..0x76a6`) | `1` when Chill/Sport acceleration mode = Sport (`0x20004605`). |
| `buf[2]` | `6` | `sentry_or_camp_flag` | `0x4162` | `0x20003f38` (`u8`) | CAN `0x3e2` (`0x40be..0x4160`) | Returns `1` when `(CAN_0x3e2_byte3 & 3) == 1` (`0x20003f38 == 1`). |
| `buf[2]` | `7` | `trunk_open` | `0x5d22` | `0x20003fab` (`u8`) | CAN `0x2e1` (`0x5bd8..0x5d20`) | `1` when rear trunk is open. |
| `buf[3]` | `6:0` | `battery_soc` | `0x7d9c` | `0x20004626` (`u8`) | CAN `0x33a` (`0x7d44..0x7d9a`) | 7-bit State of Charge (`0..100`%). |
| `buf[3]` | `7` | `regen_braking_active` | `0x4e52` | `0x20004471` (`u8`) | CAN `0x31f` / `0x266` (`0x4db0..0x4e50`) | `1` when regenerative braking / hold indicator is active. |
| `buf[4]` | `7:0` | `accelerator_pedal` | `0x4d0a` | `0x20004463` (`u8`) | CAN `0x118` (`0x4c58..0x4d08`) | Unsigned 8-bit accelerator pedal position (`0..100`%). |
| `buf[5..8]` | `31:0` | `odometer_km` | `0x7e42(0)` | `0x2000416c` (`u32` @ `0x16c(gp)`) | CAN `0x3b6` / `0x3d8` (`0x7e10..0x7e40`) | Little-endian `u32` odometer (called with `a0=0`). |
| `buf[9..12]` | `31:0` | `trip_distance` | `0x7e42(1)` | `0x20004630` (`u32`) | CAN `0x3b6` / `0x3d8` (`0x7e10..0x7e40`) | Little-endian `u32` trip distance (called with `a0=1`). |
| `buf[13..14]` | `15:0` | `elevation_m` | `0x7dda` | `0x20004170` (`u16` @ `0x170(gp)`) | CAN `0x3d8` (`0x7da0..0x7dd8`) | Little-endian `u16` GPS elevation / altitude. |
| `buf[15..16]` | `15:0` | `bms_power_raw` | `0x4fe0` | `0x200040f8` (`u16` @ `0xf8(gp)`) | CAN `0x312` / `0x266` (`0x4fac..0x4fde`) | Little-endian `u16` battery/motor power metric. |
| `buf[17..18]` | `15:0` | `rated_range_km` | `0x80e6` | `0x20004154` (`u16` @ `0x154(gp)`) | CAN `0x33a` (`0x7f88..0x80e4`) | Little-endian `u16` remaining range. |
| `buf[19..20]` | `15:0` | `trip_time_or_energy` | `0x01e8` | `0x20004078` (`u16` @ `0x78(gp)`) | Timer / energy accumulator (`0x01a0..0x01e6`) | Little-endian `u16` accumulated drive duration / energy counter. |
| `buf[21..22]` | `15:0` | `brake_temp_metric` | `0x5442` | `0x200044e4` (`u16`) | CAN `0x3fe` (`0x5378..0x5440`) | Little-endian `u16` brake temperature / thermal estimate. |
| `buf[23]` | `7:0` | `hvac_driver_temp` | `0x30a0` | `0x20004318` (`u8`) | CAN `0x20c` (`0x2f1e..0x309e`) | Driver climate setpoint (`raw = temp_C * 2`). |
| `buf[24]` | `7:0` | `hvac_passenger_temp` | `0x30aa` | `0x20004319` (`u8`) | CAN `0x20c` (`0x2f1e..0x30a8`) | Passenger climate setpoint (`raw = temp_C * 2`). |
| `buf[25]` | `7:0` | `cabin_temp` | `0x308c` | `0x2000431a` (`u8`) | CAN `0x243` / `0x321` (`0x2f1e..0x308a`) | Cabin interior temperature. |
| `buf[26]` | `7:0` | `outside_temp` | `0x3096` | `0x2000431b` (`u8`) | CAN `0x321` (`0x2f1e..0x3094`) | Ambient exterior temperature. |
| `buf[27]` | `7:0` | `bms_max_temp` | `0x517e` | `0x200044b2` (`u8`) | CAN `0x312` / `0x333` (`0x50c0..0x517c`) | Battery pack maximum temperature. |
| `buf[28]` | `7:0` | `bms_min_temp` | `0x510a` | `0x200044b1` (`u8`) | CAN `0x312` / `0x333` (`0x50c0..0x5108`) | Battery pack minimum temperature. |
| `buf[29..30]` | `15:0` | `cell_voltage_max_mv` | `0x51f6` | `0x2000410a` (`u16` @ `0x10a(gp)`) | CAN `0x333` (`0x5188..0x51f4`) | Little-endian `u16` brick/cell voltage metric. |
| `buf[31]` | `1:0` | `left_blindspot` | `0x2a94` | `0x200042d4` (`u8`) | CAN `0x39d` / `0x238` (`0x2a24..0x2a92`) | 2-bit left blind-spot / lane warning (`0`=Clear, `1`=Warn1, `2`=Warn2/Chime). |
| `buf[31]` | `3:2` | `right_blindspot` | `0x2a9e` | `0x200042d5` (`u8`) | CAN `0x39d` / `0x238` (`0x2a24..0x2a9c`) | 2-bit right blind-spot / lane warning (`(val & 3) << 2`). |
| `buf[31]` | `7:4` | `UNPACKED_NIBBLE` | — | Zeroed by `memset` | — | **4 free bits (`bits 7:4` of `buf[31]`)** never written by `0xb3e0`. |
| `buf[32]` | `7:0` | `UNPACKED_BYTE` | — | Zeroed by `memset` | — | **8 free bits (entire `buf[32]`)** allocated in the 33-byte (`0x21`) buffer but never written by `0xb3e0`. |

#### 1.3 High-Value CAN Signals Decoded in RAM Cache But NOT Packed into `0xB0`
The firmware already decodes rich vehicle state into RAM that is **not** surfaced in `buf[0..31]` of `0xB0` (even though **12 bits** in `buf[31..32]` are sitting zeroed in every `0xB0` packet!):
1. **Individual Passenger & Rear Door States (`CAN 0x102` / `0x103`)**:
   - `buf[1] bit 7` only reports `driver_door_open` (`0x5d42` -> `0x20003fa9`).
   - Front-Right (`0x128(gp)`), Rear-Left (`0x126(gp)`), and Rear-Right (`0x127(gp)`) open/closed states are tracked in RAM (`0x57f2..0x5cfc`) for rule triggers `0x72..0x7B`, plus a 4-door bitmask at `0x20003fac..0x20003faf`, but are omitted from `0xB0`.
2. **Brake Pedal Pressed (`CAN 0x118` / `0x39d`)**:
   - Decoded into `0x20004460` / `0x200042d2` (getter `0x2a60`), used by ambient light and blind-spot logic, but not packed into `0xB0`.
3. **Seatbelt Buckled States (`CAN 0x3e2`)**:
   - Driver (`0xfc(gp)`), Front Passenger (`0xfd(gp)`), and Rear (`0xfe(gp)`) seatbelt states are decoded at `0x4182..0x4200` for triggers `0x78/0x79`, `0x80/0x81`, `0x88/0x89`, but not packed into `0xB0`.
4. **Window Open/Close States (`CAN 0x219` / `0x3464..0x3516`)**:
   - All 4 window states are tracked at `0xed(gp)` (FL), `0xee(gp)` (RL), `0xef(gp)` (RR), `0xf0(gp)` (FR), and `0xf1(gp)` (all windows closed/open) for triggers `0x76/0x77`, `0x7e/0x7f`, `0x82..0x87`.
5. **TPMS Tire Pressures (`CAN 0x31f` at `0x4db0..0x4e50`)**:
   - Decoded in `0x4db0` into RAM cache, and raw CAN slots `4` and `1` can also be queried via BLE command `0xD2` (`0xc07e..0xc160`), which calls `0x028e(1, 4, sp+0x10)` and `0x028e(1, 1, sp+0x4)` and returns a `0xD2` BLE packet with 16-bit values.
6. **Steering Angle & Wiper/Stalk State (`CAN 0x249` / `0x129` at `0x45a2`)**:
   - Left/Right stalk and wiper mode states (`0x45a2..0x4690`) and steering wheel buttons/scroll wheels (`CAN 0x3c2` at `0x36c0..0x39d4`) are decoded in real time.

---

### Part 2: `0xAB` Rule / Shortcut Engine (`0xe310`) & Complete Trigger/Action Catalog

#### 2.1 How the Firmware Evaluates Rules (`0xe310..0xe520`, `0xe950..0xee00`)
When any vehicle event or button press occurs, the firmware calls `0xe310(a0 = trigger_id)`:
1. **Master Shortcut Disable Check (`0xe314..0xe330`)**:
   - Reads config pointer `s2 = *(gp + 0x74)` (`0x20004074`).
   - Checks bit 4 (`0x10`) of config byte `4(s2)`. If set (`shortcuts_disabled == 1`), only triggers `0x02`, `0x03`, and `0x04` (Right Scroll Wheel Double/Triple/Long Press, used as the emergency re-enable gesture!) are allowed to execute; all other triggers return immediately.
2. **Primary Rule Table Scan (`0xAB` Table — `0xe332..0xe376`)**:
   - Base pointer: `s1 = *(gp + 0x80)` (`0x20004080`), pointing to a 256-byte buffer in RAM backed by DataFlash `0x00007200`.
   - Loops `s0` from `0` to `0xFE` in steps of `2` (**127 rule pairs**, bytes `0..253`; byte `254` is magic `0x5B`, byte `255` is rule count):
     - `trigger_byte = table[s0]`, `action_byte = table[s0 + 1]`.
     - If `trigger_byte == a0`, calls `0xd16e(action_byte)`!
     - **Important**: It does **not** `break` on the first match! If multiple rule slots in `0xAB` share the same `trigger_byte`, **all matching actions execute sequentially** in a single `0xe310` pass (macro chaining!).
3. **Secondary & Tertiary Rule Tables (`0xAE` at `*(gp+0x84)` & `0xAC` at `*(gp+0x88)` — `0xe356..0xe376`, `0xebfa..0xee00`)**:
   - After scanning the 127 `0xAB` pairs, `0xe310` loops `s0 = 0..35` (`0x24` entries, 7 bytes per entry = 252 bytes) over `*(gp+0x84)` (`0xAE`, flash `0x7100`) and `*(gp+0x88)` (`0xAC`, flash `0x7000`):
     - Each 7-byte entry has a **9-bit trigger ID**: `trigger_9bit = entry[0] | ((entry[2] & 1) << 8)`.
     - If `trigger_9bit == a0` (or when triggered via `0xe950` for 9-bit ambient-light/state events `0x100+`), calls `0xebfa(entry_ptr, table_select)` (`a1=0` for `0xAE`, `a1=1` for `0xAC`).
4. **BLE Rule Management Commands (`0xbc76..0xc580`)**:
   - `0xA1 [trigger, action]` (`0xc196`): Add or update a `[trigger, action]` pair in `*(gp+0x80)` (`0xAB` table) and schedule flash write flag `0x02`.
   - `0xA2 [trigger, action]` (`0xc1b0`): Delete matching `[trigger, action]` pair from `*(gp+0x80)` by shifting subsequent pairs down.
   - `0xA7 [0x01]` (`0xc28a`): Clear all `0xAB` rules (`tmos_memset(*(gp+0x80), 0, 0xFF)`, set magic `0x5B` at offset `0xFE`).
   - `0xA9 [0x01]` (`0xc2f6`): Read back all active `0xAB` rules; firmware replies with `0xAB` notification containing `[count, trig_0, act_0, ...]`.

#### 2.2 Complete Firmware Trigger ID Catalog (`a0` passed to `0xe310`)
By tracing all 33 direct call sites to `0xe310` and the 5 self-relative jump tables inside `0x5f0a` (`0x1116c`, `0x11180`, `0x111f8`, `0x11344`, `0x1136c`) plus helper state machines `0x6896` (500ms multi-click/long-press timer), `0x5556` (door state machine), `0x6992` (two-state edge detector), `0x022e` (speed hysteresis band), and `0x80ec` (Drive/AP-guarded trigger), here is the complete trigger map in `V1.5.00`:

| Trigger ID Range | Source Function / Jump Table | Vehicle Event / Button Gesture |
|---|---|---|
| `0x01` | `0x5f6e` (`event 0x05`, `a1=2`, `a2=2`) | Right Scroll Wheel Button — **Single / Double Press** (`CAN 0x3c2`) |
| `0x02` | `0x5fde` (`event 0x05`, `a1=3`, `a2=2`) | Right Scroll Wheel Button — **Triple Press** (also works when shortcuts disabled) |
| `0x03` | `0x646c` (`event 0x05`, `a2=3` hold) | Right Scroll Wheel Button — **Long Press (>500ms)** (also works when shortcuts disabled) |
| `0x04` | `0x6036` (`event 0x0d`, `a1=2`, `a2=2`) | Left Scroll Wheel Button — **Double Press** (`CAN 0x3c2`) |
| `0x05` | `0x6036` (`event 0x0d`, `a1=3`, `a2=2`) | Left Scroll Wheel Button — **Triple Press** |
| `0x06` | `0x646c` (`event 0x0d`, `a2=3` hold) | Left Scroll Wheel Button — **Long Press (>500ms)** |
| `0x07..0x09` | `0x111f8` (`event 0x01`, `a1=1,2,3`) | Right Scroll Wheel **Tilt Left** — Single (`0x07`), Double (`0x08`), Triple (`0x09`) |
| `0x0A` | `0x11344` (`event 0x01`, `a2=3`) | Right Scroll Wheel **Tilt Left** — Long Press (`0x0A`) |
| `0x0B..0x0D` | `0x111f8` (`event 0x02`, `a1=1,2,3`) | Right Scroll Wheel **Tilt Right** — Single (`0x0B`), Double (`0x0C`), Triple (`0x0D`) |
| `0x0E` | `0x11344` (`event 0x02`, `a2=3`) | Right Scroll Wheel **Tilt Right** — Long Press (`0x0E`) |
| `0x0F..0x11` | `0x111f8` (`event 0x0a`, `a1=1,2,3`) | Left Scroll Wheel **Tilt Left** — Single (`0x0F`), Double (`0x10`), Triple (`0x11`) |
| `0x12` | `0x11344` (`event 0x0a`, `a2=3`) | Left Scroll Wheel **Tilt Left** — Long Press (`0x12`) |
| `0x13..0x15` | `0x111f8` (`event 0x0c`, `a1=1,2,3`) | Left Scroll Wheel **Tilt Right** — Single (`0x13`), Double (`0x14`), Triple (`0x15`) |
| `0x16` | `0x11344` (`event 0x0c`, `a2=3`) | Left Scroll Wheel **Tilt Right** — Long Press (`0x16`) |
| `0x17..0x2A` | `0x111f8` / `0x11344` (`events 0x13..0x1a`) | Highland / Steering Wheel Buttons (`CAN 0x3e2` at `0x4210..0x4256`): Single, Double, Triple, and Long Press for 8 steering wheel buttons (`0x13..0x1A`). |
| `0x2B` | `0x3712` / `0x37d0` (`CAN 0x3c2`) | Right Scroll Wheel **Scroll Up** (when custom scroll hook active) |
| `0x2C` | `0x111f8` (`event 0x04`, `a1=2`) | Right Scroll Wheel **Scroll Down** / Custom Gesture |
| `0x2D` | `0x384a` (`CAN 0x3c2` at `0x382e`) | Left Scroll Wheel **Scroll Up** (when custom scroll hook active) |
| `0x2E` | `0x3812` (`CAN 0x3c2` at `0x37e8`) | Left Scroll Wheel **Scroll Down** (when custom scroll hook active) |
| `0x2F..0x3A` | `0x111f8` / `0x11344` (`events 0x1f..0x22`) | Additional Steering / Stalk Buttons (`0x42d0..0x4302`): Single, Double, Triple, Long Press (`0x2F..0x3A`). |
| `0x3B..0x4E` | `0x111f8` / `0x11344` (`events 0x2b..0x36`) | Door Panel Window Switch Clicks (`0x389a..0x38b0` & `0x4258..0x42cc`): Single/Double/Triple/Long Press on FL/FR/RL/RR window switches (`0x3B..0x4E`). |
| `0x4F..0x5A` | `0x111f8` / `0x11344` (`events 0x39..0x3d`) | Right Gear Stalk (`CAN 0x118` at `0x4b82..0x4b9a`): Stalk Up / Half-Up / Down / Half-Down / Park Button — Single, Double, Triple, Long Press (`0x4F..0x5A`). |
| `0x5B..0x5E` | `0x11180` (`events 0x3f..0x42`, `a2=0`) | Gear Shift Transitions (`0x4c9a`): Shift into **Park** (`0x5B`), **Reverse** (`0x5C`), **Neutral** (`0x5D`), **Drive** (`0x5E`). |
| `0x5F..0x66` | `0x111f8` / `0x11344` (`events 0x43..0x45`) | Left Turn/Wiper Stalk (`CAN 0x249` at `0x45dc..0x45f4`): Wiper Button / Stalk Pull / Stalk Push — Single, Double, Triple, Long Press (`0x5F..0x66`). |
| `0x67..0x6D` | `0x111f8` / `0x11344` (`events 0x49..0x4a`) | Center Console / Hazard / Glovebox Button (`CAN 0x3e2` at `0x40f6..0x411c`): Single, Double, Triple, Long Press (`0x67..0x6D`). |
| `0x6E` | `0x11180` (`event 0x4c`, `a2=0`, `0x5262`) | **Charge Port / Charging State** transition (`0x5262` -> `event 0x4c`). |
| `0x70..0x71` | `0x11180` (`events 0x4e..0x4f`, `a2=0`) | `CAN 0x3e2` byte 3 bits `1:0` transition (`0x413c..0x414c`): State=1 (`0x70`), State!=1 (`0x71`). |
| `0x72 / 0x73` | `0x5cd8` (`0x6992` on `0x126(gp)`) | **Rear-Left Door** Open (`0x72`) / Close (`0x73`). |
| `0x74 / 0x75` | `0x5808` (`0x6992` on `0x128(gp)`) | **Front-Right (Passenger) Door** Open (`0x74`) / Close (`0x75`). |
| `0x76 / 0x77` | `0x347a` (`0x6992` on `0xed(gp)`) | **Front-Left Window** Open (`0x76`) / Close (`0x77`). |
| `0x78 / 0x79` | `0x41a0` (`0x6992` on `0xfc(gp)`) | **Driver Seatbelt** Buckled (`0x78`) / Unbuckled (`0x79`). |
| `0x7A / 0x7B` | `0x5cfc` (`0x6992` on `0x127(gp)`) | **Rear-Right Door** Open (`0x7A`) / Close (`0x7B`). |
| `0x7C / 0x7D` | `0x5846` (`0x6992` on `0x129(gp)`) | **Front-Left (Driver) Door** Open (`0x7C`) / Close (`0x7D`). |
| `0x7E / 0x7F` | `0x34cc` (`0x6992` on `0xf0(gp)`) | **Front-Right Window** Open (`0x7E`) / Close (`0x7F`). |
| `0x80 / 0x81` | `0x41e0` (`0x6992` on `0xfd(gp)`) | **Front Passenger Seatbelt** Buckled (`0x80`) / Unbuckled (`0x81`). |
| `0x82 / 0x83` | `0x3516` (`0x6992` on `0xf1(gp)`) | **All 4 Windows** Open (`0x82`) / Closed (`0x83`). |
| `0x84 / 0x85` | `0x3496` (`0x6992` on `0xee(gp)`) | **Rear-Left Window** Open (`0x84`) / Close (`0x85`). |
| `0x86 / 0x87` | `0x34b0` (`0x6992` on `0xef(gp)`) | **Rear-Right Window** Open (`0x86`) / Close (`0x87`). |
| `0x88 / 0x89` | `0x4200` (`0x6992` on `0xfe(gp)`) | **Rear Seatbelt** Buckled (`0x88`) / Unbuckled (`0x89`). |
| `0x8A` | `0x7fd4` / `0x8086` (`CAN 0x257` speed) | **Vehicle Stopped (`speed == 0`)** while in Drive (also resets speed band latches `0x15a..0x15f(gp)`). |
| `0x8B` | `0x7fe6` (`0x022e` on `0x15a(gp)`) | **Speed Reaches `5..10` km/h** in Drive (one-shot until stop). |
| `0x8C` | `0x7ff8` (`0x022e` on `0x15b(gp)`) | **Speed Reaches `15..20` km/h** in Drive (one-shot until stop). |
| `0x8D` | `0x800a` (`0x022e` on `0x15c(gp)`) | **Speed Reaches `25..30` km/h** in Drive (one-shot until stop). |
| `0x8E` | `0x8020` (`0x022e` on `0x15d(gp)`) | **Speed Reaches `35..40` km/h** in Drive (one-shot until stop). |
| `0x8F` | `0x8036` (`0x022e` on `0x15e(gp)`) | **Speed Reaches `45..50` km/h** in Drive (one-shot until stop). |
| `0x90` | `0x804c` (`0x022e` on `0x15f(gp)`) | **Speed Reaches `55..60` km/h** in Drive (one-shot until stop). |
| `0x91..0xA2` | `0x111f8` / `0x11344` (`events 0x53..0x57`) | Seat / Lumbar / Console Physical Buttons (`0x8538..0x8848`): Single, Double, Triple, Long Press (`0x91..0xA2`) and Hold-Release (`0xB1..0xB5` via `0x1136c`). |
| `0xA3 / 0xA4` | `0x570e` / `0x56a8` (`0x5556` door helper) | **Front Trunk (Frunk)** Open (`0xA3`) / Close (`0xA4`). |
| `0xA5 / 0xA6` | `0x570e` / `0x56a8` (`0x5556` door helper) | **Rear Trunk** Open (`0xA5`) / Close (`0xA6`). |
| `0xA7 / 0xA8` | `0x57b0` / `0x58a2` (`CAN 0x102/0x103`) | **Vehicle Lock / Unlock** state transitions (`0xA7` / `0xA8`). |
| `0xA9 / 0xAC` | `0x2a6c` (`CAN 0x39d` blindspot) | **Blind-Spot Warning + Turn Signal Active**: Left (`0xA9`) / Right (`0xAC`). |
| `0xAA / 0xAD` | `0x8192` / `0x81bc` (`0x80ec` Drive/AP guard) | **Autopilot / Lane / Speed Limit Warning** triggers (`0xAA` / `0xAD`, guarded by `0x80ec`: only fires in Drive when AP state matches `*(gp+0x74)+1` config). |
| `0xAB / 0xAE` | `0x2c28` (`CAN 0x39d` / `0x2b6`) | **Autopilot Engaged (`0xAB`) / Disengaged (`0xAE`)** (or AP Hands-On Nag stages). |
| `0xAF / 0xB0` | `0x5022` (`CAN 0x312/0x333` BMS) | **Battery Preconditioning / Heater Started (`0xAF`) / Stopped (`0xB0`)**. |
| `0xB1..0xB5` | `0x1136c` (`events 0x53..0x57`, `a2=4`) | Seat / Console Button **Long-Press Release** (`0xB1..0xB5`). |
| `0xB6..0xB9` | `0x26ea..0x2818` (`CAN 0x3f5` lights) | **Turn Signal / High-Beam / Lighting** transitions: Left Turn (`0xB6`), Right Turn (`0xB7`), Hazard/High-Beam On (`0xB8`), Off (`0xB9`). |
| `0xBA / 0xBB` | `0x5300` (`CAN 0x33a` charging) | **Charging Started (`0xBA`) / Charging Stopped (`0xBB`)**. |
| `0xBC / 0xBD` | `0x6ea6` / `0x6e48` (`CAN 0x339/0x273`) | **Touchscreen / Keep-Screen / Sentry** state transitions (`0xBC` / `0xBD`). |

#### 2.3 Complete Firmware Action ID Catalog (`0xd16e`, Jump Table `0x11710`, IDs `0x01..0xFD`)
`0xd16e` subtracts `1` from `action_id` and dispatches `0x01..0xFD` (253 entries; `0x00`, `0xFE`, `0xFF` are out-of-range NOPs).
Cross-referencing all 253 entries in `0x11710` reveals the exact handler groups and **two major undocumented action subsystems**:

| Action ID Range | Handler Target(s) | Functional Behavior |
|---|---|---|
| `0x01..0x08` (1–8) | `0xf296` (`a1=200`, `a0=bitmask`) | **Passenger / Driver Seat Motor Direct Move** (`bitmask` = `0x04, 0x08, 0x80, 0x40, 0x01, 0x02, 0x20, 0x10`: Fore/Aft, Height Up/Down, Backrest Tilt Forward/Back, Cushion Tilt). |
| `0x09` (9) | `0x7350` | **Open Charge Port**. |
| `0x0A..0x0D` (10–13) | `0x5b8e(1, 4, 7, 10)` | **Door Unlatch / Pop Open**: FL (`0x0A`), FR (`0x0B`), RL (`0x0C`), RR (`0x0D`). |
| `0x0E..0x11` (14–17) | `0x76ae(0..3)` | **Seat Heater / Steering Heater / Accel Mode** step (`a0 = action_id - 14 = 0..3`). |
| `0x12..0x14` (18–20) | `0xe4e4(0/1, 1)` | **Enable (`0x12`), Disable (`0x13`), or Toggle (`0x14`) Shortcut Rule Engine** (modifies bit `0x10` of `*(gp+0x74)+4` and saves to flash). |
| `0x15..0x17` (21–23) | `0x2ac0` / `0x2aa8` | **Blind-Spot Monitoring / Chime**: Toggle (`0x15`), Off (`0x16`), On (`0x17`). |
| `0x18..0x1B` (24–27) | `0x5e90`, `0x77fc`, `0x7344`, `0x6de0` | **Glovebox (`0x18`), Frunk (`0x19`), Trunk (`0x1A`), Keep Screen On (`0x1B`)**. |
| `0x1C..0x25` (28–37) | `0x4fac`, `0x508e`, `0x7386` | **Battery Preconditioning (`0x1C..0x1E`), BMS Heater (`0x1F..0x22`), Charge Lock/Unlock (`0x23..0x25`)** Off/On/Toggle. |
| `0x26..0x27` (38–39) | `0xd330` (NOP) | Reserved / NOP. |
| `0x28..0x2A` (40–42) | `0x5bda`, `0x5d2c`, `0x5d32` | **Central Locks**: Toggle Lock/Unlock (`0x28`), Lock (`0x29`), Unlock (`0x2A`). |
| `0x2B..0x2C` (43–44) | `0x74f0`, `0x7514` | **Mirrors Fold/Unfold Toggle (`0x2B`), Child Lock Toggle (`0x2C`)**. |
| `0x2D..0x41` (45–65) | `0x3a64`, `0x495a`, `0x739c..0x752c`, `0xad64` | **Windows, Sunshade, Defrost, Dome Lights, & Ambient Light Toggle/Off/On** (`0x3F..0x41` toggle/disable/enable ambient light bits in `*(gp+0x74)+4`). |
| `0x42..0x45` (66–69) | `0x6d30(0x46 - action_id, 0)` | **Wiper Speed Direct Select**: Off / I / II / III / Auto (`a0 = 4, 3, 2, 1`). |
| `0x46..0x4B` (70–75) | `0x3222`, `0x3200` | **HVAC Climate Power (`0x46..0x48`) & Recirculation (`0x49..0x4B`)** Toggle/Off/On. |
| `0x4E..0x53` (78–83) | `0xf378`, `0xf436` | **Seat Adjustment Continuous Hold / Stop** (used with button hold/release triggers). |
| `0x54..0x59` (84–89) | `0x6c90(0)`, `0x6d30(0x5A - action_id, 1)` | **Wiper Washer / Wiper Step Control**. |
| `0x5A..0x62` (90–98) | `0x3a64`, `0x495a`, `0x739c..0x7464` | **Window Vent / Close All, Steering Wheel Heat, Defrost, Camp/Dog Mode toggles**. |
| `0x63..0x68` (99–104) | `0x4930`, `0x4d3e` | **Gear / Autopilot / TACC Stalk Simulation**: Park (`0x63`), Drive (`0x64`), Reverse (`0x65`), Neutral (`0x66`), Toggle D/R (`0x68`). |
| `0x69..0x78` (105–120) | `0x6c90`, `0x4a2e`, `0x4946`, `0x3a50`, `0x3a00`, `0x4b4a` | **Turn Signals (3-blink / Continuous Left & Right), High-Beam Flash, Horn, Hazard Lights**. |
| `0x7A..0x87` (122–135) | `0x5b8e`, `0x7b0c`, `0x7b1e` | **Extended Door/Latch/Window/Lock CAN Actions** (`0x5b8e` modes `2..15`). |
| `0x88..0x95` (136–149) | `0x33e2`, `0x3a00`, `0x3a30` | **HVAC Fan Speed / Temperature / Seat Heater Presets** (`0x33e2` modes `1..18`). |
| `0x96..0x9C` (150–156) | `0x7692`, `0x5b8e(16..19)` | **Acceleration Mode (Chill/Sport Toggle `0x96`, Chill `0x97`, Sport `0x98`)** & Door actions (`0x99..0x9C`). |
| `0x9F..0xA0` (159–160) | `0x7746`, `0x773a` | **ESP / Traction / Drift or Suspension Toggles**. |
| `0xAA..0xB3` (170–179) | `0x2dea`, `0x7a82(0..3)`, `0x40ac`, `0x5356`, `0x2ea2` | **Autopilot / Regenerative Braking Level (`0xAB..0xAE` = 100%/75%/50%/0%) / Media / BMS actions**. |
| `0xB4..0xC0` (180–192) | `0x1436`, `0x14ea..0x171e` | **Passenger / Driver Seat Easy-Entry & Co-Pilot Seat Move Actions**. |
| **`0xC8..0xD1` (200–209)** | **`0xf450(0..9)` (UNDOCUMENTED)** | **10-Slot Custom Seat Memory Recall**: `0xC8..0xCC` (slots `0..4`) recall Driver Seat presets; `0xCD..0xD1` (slots `5..9`) recall Passenger Seat presets! Each slot reads an 8-byte target position from `*(gp+0x74) + (slot+2)*8` (written by BLE command `0xAA`) and drives the seat motors until raw CAN slot `0x10`/`0x11` matches! |
| **`0xE1..0xF5`, `0xF7..0xF9` (225–249)** | **`0x0e6c` -> `0x05d2` (UNDOCUMENTED)** | **BLE Peripheral Sub-Beacon Broadcast**: Writes command code (`0x00`, `0xFC`, `0xFD`, `0xFF`, `0x00..0x11`, `0xC8..0xCA`) to `0xbd(gp)` and triggers TMOS task `0xbc(gp)` (`0x05d2`), which temporarily switches the CH583's BLE advertising payload (`GAPROLE_ADVERT_DATA`) for 500ms to a 26-byte manufacturer-specific broadcast (`Company ID 0x4554`, `"TSL"`, rolling counter `0xb8(gp)`, command byte `0xbd(gp)`) to control wireless sub-peripherals (external ambient light controllers, wireless buttons, power frunk/trunk boxes)! |
| **`0xFA..0xFC` (250–252)** | **`0xd0d0` (UNDOCUMENTED)** | **Auto-Volume / Anti-Nag Feature Control**: Toggles (`0xFA`), Enables (`0xFB`), or Disables (`0xFC`) bit 3 (`0x08`) of `*(gp+0x74)+4` and saves to flash! |
| **`0xFD` (253)** | **`0xdef0` (`0x1684` + timer `0xd9b8`)** | **Timed Co-Pilot Seat Return / Reset Macro** (1000ms timer). |

---

### Part 3: Concrete `TSL Cmd` Phone-Side & Firmware Automation Opportunities

#### 3.1 Phone-Side Automations in `TSL Cmd` (Zero Firmware Modification Required)
Because `TSL Cmd` receives the live `0xB0` stream (and can send `0xA1`/`0xA2`/`0xAA` config writes or `0xD2` raw CAN queries), `TSL Cmd` can immediately implement:
1. **Multi-Action Macro Chains on Any Single Trigger**:
   - Because `0xe310` (`0xe332..0xe34c`) scans all 127 slots of `*(gp+0x80)` without breaking on the first match, `TSL Cmd` can let users bind **multiple actions to a single trigger** (e.g., `Trigger 0x5B [Shift to Park]` -> `Action 0x2A [Unlock Doors]` + `Action 0x47 [Climate Off]`) simply by writing multiple `[trigger, action]` pairs with the same `trigger` byte via `0xA1`!
2. **Speed-Band & Arrival Automations (Triggers `0x8A..0x90` + Live `0xB0` Telemetry)**:
   - Expose the firmware's built-in hysteresis speed triggers (`0x8A` Stop, `0x8B` 5–10 km/h, `0x8C` 15–20 km/h, `0x8D` 25–30 km/h, `0x8E` 35–40 km/h, `0x8F` 45–50 km/h, `0x90` 55–60 km/h) in `TSL Cmd`'s rule editor (e.g., auto-fold mirrors or switch camera/ambient mode at low speed, auto-lock at 15 km/h).
   - On the phone side, combine `0xB0` `speed`, `gear`, `autopilot_active`, `left_blindspot` / `right_blindspot`, and `turn_signal` for spoken audio alerts, speed-compensated phone media volume, or automatic navigation app launching when shifting out of Park (`buf[1] bits 3:1` transitioning `1 -> 2` or `4`).
3. **10-Slot Custom Seat Memory Manager (`0xAA` BLE Command + Actions `0xC8..0xD1`)**:
   - Expose the undocumented 10-slot seat memory subsystem (`0xC8..0xCC` Driver slots 0–4, `0xCD..0xD1` Passenger slots 5–9) in `TSL Cmd`, allowing users to snapshot current seat positions (or write presets via `0xAA`) and trigger them from door/gear/button shortcuts (e.g., Passenger Nap Mode or Kid Car-Seat Clearance).
4. **Shortcut Toggle & Auto-Volume Gesture Binding (Actions `0x12..0x14` & `0xFA..0xFC`)**:
   - Let users bind a steering wheel gesture (e.g., Right Scroll Triple Press `0x02` or Long Press `0x03`) to Action `0x14` (Toggle All Shortcuts — Valet/Service Mode) or Action `0xFA` (Toggle Auto-Volume/Anti-Nag).
5. **Thermal & Charging Dashboard Alerts (`buf[2] bit 1`, `buf[3]`, `buf[27..30]`, `buf[21..22]`)**:
   - Use `battery_heater_on` (`buf[2] bit 1`), `bms_max_temp` (`buf[27]`), `bms_min_temp` (`buf[28]`), `cell_voltage_max_mv` (`buf[29..30]`), and `brake_temp_metric` (`buf[21..22]`) in `TSL Cmd` to provide real-time preconditioning notifications ("Battery ready for fast charging") and brake/battery thermal warnings.

#### 3.2 Optional Firmware Patch Opportunities (High Value, Minimal Byte Footprint)
1. **Pack Missing Signals into the 12 Free Bits of `0xB0` (`buf[31] bits 7:4` & `buf[32] bits 7:0`)**:
   - `0xb3e0` already allocates and sends 33 bytes (`0x21`), leaving `buf[31] bits 7:4` and all of `buf[32]` zeroed.
   - A tiny patch at the end of `0xb3e0` (`0xb748..0xb758`) can pack:
     - `buf[31] bit 4`: `brake_pedal_active` (`0x20004460` / `0x2a60`)
     - `buf[31] bits 7:5`: Individual door open bits for `FR` (`0x128(gp)`), `RL` (`0x126(gp)`), `RR` (`0x127(gp)`)
     - `buf[32] bits 2:0`: Seatbelt buckled bits (`0xfc(gp)`, `0xfd(gp)`, `0xfe(gp)`)
     - `buf[32] bits 6:3`: 4-window open/closed bits (`0xed(gp)..0xf0(gp)`)
     - `buf[32] bit 7`: Shortcut engine enabled (`*(gp+0x74)+4 bit 4`)
   - This requires **zero change to the 38-byte BLE packet length** and maintains 100% backward compatibility with existing `0xB0` parsers!

---

## Architecture
```
CAN Bus Frames (0x102, 0x118, 0x20c, 0x249, 0x257, 0x2e1, 0x312, 0x333, 0x33a, 0x39d, 0x3c2, 0x3e2, 0x3f5, 0x3fe)
   │
   ├──► CAN Decoders & Edge Detectors
   │      ├─► RAM State Cache (gp-relative 0x20004070..0x20004630 & 0x20003fa0..0x20003fff)
   │      │     └─► 31 Getter Functions ──► 0xb3e0 (0xB0 33-Byte Packer) ──► 0x0d02 (FFF4 Notify)
   │      │
   │      └─► Event & Gesture State Machines
   │            ├─► 0x6896 (500ms Multi-Click / Long-Press / Release State Machine)
   │            │     └─► 0x5f0a (5 Jump Tables: 0x1116c, 0x11180, 0x111f8, 0x11344, 0x1136c)
   │            ├─► 0x5556 (Door/Trunk State Helper) & 0x6992 (Two-State Edge Trigger Helper)
   │            └─► 0x022e (Speed Band Hysteresis 0x8B..0x90) & 0x80ec (Drive/AP Guard 0xAA/0xAD)
   │                  │
   │                  ▼
   └──► 0xe310 (Rule Engine Evaluator, a0 = Trigger ID 0x01..0xBD)
          ├─► Scans 127 Primary Rules @ *(gp+0x80) [0xAB Table, DataFlash 0x7200]
          │     └─► Calls 0xd16e(action_id) ──► 0x11710 (253-Entry Jump Table 0x01..0xFD)
          │           ├─► Vehicle CAN Actions (0x01..0xC0)
          │           ├─► 0xf450: 10-Slot Seat Memory Presets (0xC8..0xD1, config via 0xAA)
          │           ├─► 0x0e6c -> 0x05d2: BLE Sub-Beacon Broadcast (0xE1..0xF9)
          │           └─► 0xd0d0: Auto-Volume / Anti-Nag Toggle/On/Off (0xFA..0xFC)
          └─► Scans 36 Secondary/Tertiary Rules @ *(gp+0x84) [0xAE] & *(gp+0x88) [0xAC]
                └─► Calls 0xebfa / 0xeaec (Ambient Lighting & Parameterized Rules)
```

## Start Here
- Open `/root/.pi/agent/sessions/--root--/subagent-artifacts/outputs/9dfd5de7-7300-4a54-9f25-ad503405652a/context.md` (this file) alongside `/root/projects/TSL6-Firmware/CLEAN_ROOM_SPEC.md` (lines 120–310): it maps every byte/bit of `0xB0` (`0xb3e0`), every trigger ID (`0x01..0xBD`) entering `0xe310`, and every action ID (`0x01..0xFD`) dispatched by `0xd16e` (`0x11710`) so `TSL Cmd` can immediately expose the full rule catalog, macro chaining, and telemetry automations.
