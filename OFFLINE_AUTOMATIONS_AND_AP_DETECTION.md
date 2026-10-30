# TSL6 Firmware Deep Dive: CAN `0x39d` / `0x2b6` Driver-Assist Detection, Autonomous Scheduler, & Offline Multi-Step Automations

This document provides an instruction-accurate reverse-engineering analysis of the TSL6 runtime firmware (`work/runtime.payload.bin`, 73,728 bytes; linked code base `0x00008000`, flash alias `0x08008000`, global pointer `gp = 0x20004000`, stack pointer `sp = 0x20010000`) covering three core areas:

1. **CAN `0x39d` / `0x2b6` / `0x293` Driver-Assist & Hands-On Reminder Detection (`0x2856..0x2E80`, `0x80EC..0x8230`, `0xE3E6..0xE5F0`)**
2. **Offline Multi-Step Automations Without Phone Connection (`0xAB`, `0xAE`, `0xAC`, and `0xAA` Tables)**
3. **Verified Binary Patch: `unlock_steering_triggers_all_gears_0x8100` (`tools/firmware_patcher.py` & `analysis/patch_catalog.json`)**

> **Address Resolution Convention:** All code offsets are given as payload offsets (`0x0000..0x11FFF`) alongside their linked runtime addresses (`payload_offset + 0x8000`). All `auipc`-relative RAM addresses are resolved using the linked runtime PC (`PC_linked = payload_offset + 0x8000`), matching `gp`-relative (`gp = 0x20004000`) addressing across the entire binary.

---

## Part 1: CAN `0x39d` / `0x2b6` Driver-Assist, Hands-On Reminder Detection, & Scheduler Internals

### 1.1 CAN `0x39d` (`ID39DDAS_status`) & `0x293` Decoding (`0x2856..0x2D38`)

In the CAN RX binary-search dispatch table (`0x115D0`, searched by `0xC934`), CAN ID `0x39d` (cache index `4` on Bus 0/1) dispatches to **`0x2856`** (linked `0x0000A856`).

Note that in TSL6's CAN frame buffer convention (`a0` pointing to a 12-byte internal frame buffer):
- `0(a0)..2(a0)` = 3-byte frame metadata header (`0(a0)` = bus ID, `1(a0)..2(a0)` = 16-bit CAN ID).
- **`3(a0)..10(a0)` = CAN payload `byte[0]..byte[7]`** (i.e. `3(a0)` is `byte[0]`, `4(a0)` is `byte[1]`, `5(a0)` is `byte[2]`, `6(a0)` is `byte[3]`, `7(a0)` is `byte[4]`, `8(a0)` is `byte[5]`, `9(a0)` is `byte[6]`, `10(a0)` is `byte[7]`).

#### Step-by-Step Trace of `0x2856` (CAN `0x39d` Handler)

| Payload Offset | Linked Addr | Instruction | Decoded Signal / State Variable | Behavior & Rule Triggers Fired |
|---|---|---|---|---|
| `0x2856..0x2862` | `0x0000A856` | `jal 0x0204; bnez a0, 0x28ac` | Bus filter (`0x0204(1)`) | Accepts `0x39d` only from the active primary CAN bus (`0(a0) == *(0x200040C6)`). |
| `0x2864..0x2890` | `0x0000A864` | `lbu s1, 3(s0); andi s1, 0xf` | **`DAS_autopilotState`** = `byte[0] & 0x0F`, stored at `0x2000BF01` | Subtracts `3` and compares `<= 2`: states **`3` (Active / TACC+Autosteer), `4` (Active / Navigate on AP), `5` (Active / FSD)** set **`*(0x2000BF02) = 1`** (AP Active); all other states set **`*(0x2000BF02) = 0`**. |
| `0x2892..0x28A8` | `0x0000A892` | `beq a4, s1, 0x293e; ...` | AP State Transition Detector | When `*(0x2000BF02)` transitions `0 -> 1` or `1 -> 0` (or raw `DAS_autopilotState` changes):<br>• Calls `0xB86E` (marks BLE `0xB0` telemetry dirty).<br>• Calls **`0xE310(0x4E)`** when `*(0x2000BF02) == 1` (**Trigger `0x4E`: Autopilot Engaged**), or **`0xE310(0x4F)`** when `*(0x2000BF02) == 0` (**Trigger `0x4F`: Autopilot Disengaged**).<br>• Calls `0x2318(is_active)` (AP auto-restore state machine).<br>• Calls `0x49C4()` (auto high-beam / fog light hook on AP state change). |
| `0x293E..0x296E` | `0x0000A93E` | `lbu a5, 5(s0); srli a5, 2; andi a5, 0xf` | **`DAS_handsOnState`** = `(byte[2] >> 2) & 0x0F` | Normalizes the raw 4-bit `DAS_handsOnState` into a 2-bit warning stage `s1` (`0..3`):<br>• Raw `1` or `2` (`addi a4, a5, -1 <= 1`) $\rightarrow$ **`stage = 1`** (Stage 1: initial visual hands-on reminder).<br>• Raw `3` $\rightarrow$ **`stage = 2`** (Stage 2: flashing blue/white hands-on reminder).<br>• Raw `4` or `5` (`addi a5, a5, -4 <= 1`) $\rightarrow$ **`stage = 3`** (Stage 3: audible chime / urgent hands-on reminder).<br>• Any other value (`0`, `>=6`) $\rightarrow$ **`stage = 0`** (No hands-on warning). |
| `0x2970..0x29B0` | `0x0000A970` | `sb s1, -0x6b(a4); ...` | **`*(0x2000BEFD)`** = normalized `stage` (`0..3`) | If `stage != prev_stage`:<br>• Stores `*(0x2000BEFD) = stage`.<br>• Sets `*(0x2000BEFF) = (stage != 0 ? 1 : 0)` (boolean Hands-On Warning Active flag).<br>• If `*(0x2000BEFE)` (init guard) is `1`, calls **`0xE310(0xA8)`** when `stage != 0` (**Trigger `0xA8`: Hands-On Reminder Warning Started/Escalated**) or **`0xE310(0xA9)`** when `stage == 0` (**Trigger `0xA9`: Hands-On Reminder Warning Cleared**).<br>• Sets `*(0x2000BEFE) = 1`. |
| `0x29B2..0x29B4` | `0x0000A9B2` | `mv a0, s1; jal 0x2b34` | Reactive Reminder Handler (`0x2B34(stage)`) | Invokes `0x2B34(stage)` on **every** `0x39d` frame (even if `stage` did not change, so persistent warnings continue to be handled after cooldown). |
| `0x29B8..0x29E8` | `0x0000A9B8` | `lbu a5, 8(s0); srli a5, 4; andi a5, 3` | **`DAS_turnIndicatorRequest`** = `(byte[5] >> 4) & 0x03`, stored at `0x2000BF03` | Tracks AP-requested lane-change indicator (`1` = Left, `2` = Right). When it transitions to `1` or `2` and `*(0x2000BEF1) != 0`, starts a `1000 ms` timer (`0x2836`) to assist lane-change signaling. |
| `0x29EA..0x2A00` | `0x0000A9EA` | `lbu a0, 7(s0); mv a0, s0; jal 0x2a2a; ...` | Calls `0x2A2A(s0)` and `0x2C78(byte[4] & 1)` | Decodes `DAS_activationFailureStatus` (`0x2A2A`) and AP override/takeover warning (`0x2C78`). |

#### Helper Functions in `0x2A2A..0x2D38` and `0x2E2A..0x2E80`

1. **`0x2A2A` (`DAS_activationFailureStatus` / AP Availability Change)**:
   - Reads `byte[1] & 0x1F` (`lbu s0, 4(s0); c.andi s0, 0x1f`), subtracts `1` (`0x00 -> 0xFF`, `0x01 -> 0x00`, `0x02 -> 0x01`), and compares against `*(0x2000BF07)`.
   - On change (after the first frame where `*(0x2000BF08) != 0`), fires:
     - **`0xE310(0x96)`** if the new status is numerically higher than the previous value.
     - **`0xE310(0x97)`** if the new status is numerically lower than the previous value.
   - Updates `*(0x2000BF07) = s0` and `*(0x2000BF08) = 1`, and marks BLE `0xB0` telemetry dirty (`0xB86E`).

2. **`0x2B34` (Event-Driven Hands-On Reminder Auto-Dismiss / Scroll-Wheel Pulse)**:
   - Called on every CAN `0x39d` frame with `a0 = stage` (`0..3`, from `*(0x2000BEFD)`).
   - Checks settings in `*(gp+0x74)` (`0x2000C2B8`):
     - `settings[4] & 0x06`: Configured hands-on reminder threshold (`0` = Disabled, `2` = Stage 1, `4` = Stage 2, `6` = Stage 3). If `0`, returns immediately (`0x2B4A`).
     - `settings[4] & 0x20`: Suppression bit. If non-zero, returns immediately (`0x2B50`).
   - Calls `0x4D14()` (current gear) and requires **`gear == 4` (Drive)** (`0x2B5A`).
   - Matches `stage` (`s0`) against the user-configured threshold (`settings[4] & 0x06`):
     - `stage == 1` matches `(settings[4] & 0x06) == 2` (`0x2B60..0x2B6E`)
     - `stage == 2` matches `(settings[4] & 0x06) == 4` (`0x2B7C..0x2B8A`)
     - `stage == 3` matches `(settings[4] & 0x06) == 6` (`0x2BA4..0x2BB4`)
   - When matched (`0x2B8E`):
     - Reads the 2000 ms cooldown flag **`*(0x2000BF00)`**:
       - **If `*(0x2000BF00) == 0` (`0x2BB6`)**:
         1. Sets `*(0x2000BF00) = 1` and arms a **2000 ms (`0x7D0`)** software timer (`0x110A`) with callback `0x2A1A` (which clears `*(0x2000BF00) = 0` when 2.0 s elapse).
         2. If `stage == 1` and `*(gp+0x186) == 0`: calls `0x2AC0(1)` (`0x2144(1)` scroll-wheel pulse), and if `*(gp+0x188)` (vehicle type) `> 2` and `0x80E0()` (speed) `!= 0`, also calls `0x2C78(1)` (`0x2C08(1)`).
       - **If `*(0x2000BF00) != 0` (`0x2B98`)**:
         - Tail-calls `0x25B0()` (`j -0x5f0` at `0x2BA0`), which checks `*(0x2000BF04) == 0 && *(0x2000BEF3) == 1 && *(0x2000BEF1) != 0` and triggers the AP re-engage/restore sequence (`0x24C6`) if needed.

3. **`0x2C78`, `0x2CAC`, and `0x2C08` (Takeover / Override Alert & Triggers `0x50` / `0x51`)**:
   - For vehicle types `1..2` (`*(gp+0x188)` in `{1, 2}`), `0x2C78` takes `byte[4] & 0x01` from CAN `0x39d` and passes it to `0x2C08`.
   - For vehicle types `>= 3`, `0x2CAC` (CAN `0x293` handler) extracts `(byte[3] >> 5) & 1` (for types `7..8`) or `byte[3] & 1` (for other types `>= 3`) and passes it to `0x2C08`.
   - `0x2C08(alert_bit)` compares `alert_bit` against **`*(0x2000BF04)`**:
     - On change, updates `*(0x2000BF04) = alert_bit` and calls **`0xE310(0x50)`** when `alert_bit == 1` (**Trigger `0x50`: AP Takeover / Override Alert Active**) or **`0xE310(0x51)`** when `alert_bit == 0` (**Trigger `0x51`: AP Takeover / Override Alert Cleared**).

4. **`0x2E2A` & `0x2E62` (CAN `0x2b6` `ID2B6DI_state` / Brake & Chassis Status) and `0x2D08` (`0xB0` Telemetry Field)**:
   - In the CAN RX table (`0x115D0`), CAN ID `0x2b6` dispatches to **`0x2E62`**, which calls **`0x2E2A`**:
     - `0x2E2A` checks `0x0204(0)` (Bus 0 filter), then extracts `((byte[1] & 0x03) << 8) | byte[0]` (`lbu a5, 4(a0); lbu a4, 3(a0)`), divides the 10-bit unsigned value by `2` (`srli a5, 1`), and compares against `0xB0` (`176`):
       - Sets **`*(0x2000BF05) = (val > 0xB0 ? 1 : 0)`** (high brake pressure / regen threshold flag).
     - `0x2E62` also checks `(byte[1] >> 2) & 0x03 == 2` (`0x2E66..0x2E70`):
       - When true, copies the 4-byte word at `byte[2]..byte[5]` (`lw a5, 5(a0)`) into **`*(0x2000BF08)`** (`0x2E7E`) and updates **`*(0x2000BF06)`** (`0x2D8E`).
   - **`0x2D08` (Combined Driver-Assist Warning Level for BLE `0xB0` Telemetry)**:
     - Called from `0xB452` when building the 33-byte `0xB0` telemetry packet (`word0[15:14]` at `0x0C(sp)`):
       - Returns **`2`** if `0x28AC()` (`*(0x2000BF06) != 0`) is true.
       - Else returns **`1`** if `*(0x2000BF04) != 0` (AP takeover/override alert active).
       - Else returns **`3`** if `*(0x2000BEFF) == 2` (secondary hands-on flag).
       - Else returns **`0`**.

---

### 1.2 Steering-Wheel Angle (`0x129`) & The `0x80EC` Drive/AP Gate (`0x80EC..0x8230`)

In the CAN RX dispatch table (`0x115D0`), CAN ID **`0x129`** (`ID129SteeringAngle`) dispatches to **`0x811E`** (linked `0x0001011E`).

#### Signal Decoding & Hysteresis State Machine (`0x811E..0x8230`)

1. **Raw Angle Extraction (`0x811E..0x8134`)**:
   - Reads `byte[3]` (`6(a0)`) and `byte[2]` (`5(a0)`):
     ```c
     int16_t angle_tenths = (((byte[3] & 0x3F) << 8) | byte[2]) - 8192; // 0.1 deg/LSB, signed
     ```
   - Stores `angle_tenths` into **`*(int16_t*)(gp + 0x164)`** (`0x20004164`).
2. **Optional Auto Turn-Signal Cancel Hook (`0x8138..0x816E`)**:
   - If `settings[7]` bit 7 is set (`lb a5, 7(settings) < 0`), `0x4D14()` speed/gear check passes, and `abs(angle_tenths) > 24.9°` (`0xF9 = 249` tenths), calls `0x7128()` to trigger turn-signal assist.
3. **4-State Steering Angle Trigger Machine (`0x8170..0x8230`)**:
   - Uses state byte **`*(uint8_t*)(gp + 0x160)`** (`0x20004160`, values `0, 1, 2, 3`) and dispatches every transition through **`0x80EC(trigger_id)`**:

| Current State `0x160(gp)` | Angle Condition (`angle_tenths`, `0.1°/LSB`) | Physical Steering Wheel Angle | New State `0x160(gp)` | Trigger ID Passed to `0x80EC` |
|---|---|---|---|---|
| `!= 0` (`1, 2, 3`) | `(uint16_t)(angle_tenths + 60) <= 120` | **`-6.0° .. +6.0°`** (Returned to Center) | `0` | **`0xAA`** |
| `0` | `angle_tenths < -200` (`-0xC8`) | **`< -20.0°`** (Left Turn Stage 1) | `1` | **`0xAB`** |
| `0` | `angle_tenths > +200` (`+0xC8`) | **`> +20.0°`** (Right Turn Stage 1) | `1` | **`0xAE`** |
| `1` | `angle_tenths < -450` (`-0x1C2`) | **`< -45.0°`** (Left Turn Stage 2) | `2` | **`0xAC`** |
| `1` | `angle_tenths > +450` (`+0x1C2`) | **`> +45.0°`** (Right Turn Stage 2) | `2` | **`0xAF`** |
| `2` | `angle_tenths < -900` (`-0x384`) | **`< -90.0°`** (Left Turn Stage 3) | `3` | **`0xAD`** |
| `2` | `angle_tenths > +900` (`+0x384`) | **`> +90.0°`** (Right Turn Stage 3) | `3` | **`0xB0`** |

#### How `0x80EC` Gates Steering Triggers `0xAA..0xB0`

```assembly
0x0080ec: 4111      c.addi  sp, -0x10
0x0080ee: 22c4      c.swsp  s0, 8(sp)
0x0080f0: 06c6      c.swsp  ra, 0xc(sp)
0x0080f2: 2a84      c.mv    s0, a0          ; s0 = trigger_id (0xAA..0xB0)
0x0080f4: ef80ef97  jal     0x0272          ; 0x0272() -> 1 if vehicle awake (*(0x2000c205) <= 2)
0x0080f8: 19cd      c.beqz  a0, 0x8116      ; abort if vehicle asleep
0x0080fa: efc0bfc1  jal     0x4d14          ; 0x4d14() -> current gear (1=P, 2=R, 3=N, 4=D)
0x0080fe: 9147      c.li    a5, 4
0x008100: 631bf500  bne     a0, a5, 0x8116  ; STOCK GATE: abort if gear != 4 (Drive)!
0x008104: efa05f9a  jal     0x2aa8          ; 0x2aa8() -> *(0x2000bf02) (1 if Autopilot active)
0x008108: 19e5      c.bnez  a0, 0x8116      ; SAFETY GATE: abort if Autopilot is active!
0x00810a: 2285      c.mv    a0, s0
0x00810c: 2244      c.lwsp  s0, 8(sp)
0x00810e: b240      c.lwsp  ra, 0xc(sp)
0x008110: 4101      c.addi  sp, 0x10
0x008112: 6f60e01f  j       0xe310          ; tail-call rule engine 0xE310(trigger_id)
```

- **Why `0x80EC` blocks `0xAA..0xB0` during Autopilot (`0x8104..0x8108`)**: When Autosteer/FSD (`*(0x2000BF02) == 1`) is controlling the wheel, automatic steering angles must not fire user steering-angle automations.
- **Why `0x8100` (`gear != 4`) is overly restrictive in stock firmware**: Blocking `0xAA..0xB0` outside Drive prevents using steering-wheel gestures in **Park (`gear == 1`)** (e.g., turning the wheel left/right while parked to open the frunk, trunk, charge port, or glovebox) or in **Reverse (`gear == 2`)** (e.g., folding/unfolding mirrors or triggering camera/lighting actions while backing up). Part 3 documents the `unlock_steering_triggers_all_gears_0x8100` patch that replaces `0x8100` with `nop` while keeping the `0x0272` (awake) and `0x2AA8` (AP inactive) gates intact.

---

### 1.3 Autonomous Scheduler (`0xE3E6..0xE5F0`) vs Reactive CAN `0x39d` When Phone Is Disconnected

When no phone is connected over BLE, TSL6 runs **two distinct, autonomous mechanisms** for scroll-wheel / media pulse scheduling:

| Feature | Periodic Autonomous Scheduler (`0xE3E6..0xE5F0`) | Reactive CAN `0x39d` Hands-On Handler (`0x2B34`) |
|---|---|---|
| **Enable Flag / Config** | `*(gp+0x18C)` (`0x2000418C`, persisted via DataFlash `0x7000` offset `0x75`), mode in `settings[3] & 0x0F` (`0, 1, 2, 3, 0xF`). | `settings[4] & 0x06` (`2`=Stage 1, `4`=Stage 2, `6`=Stage 3) and `(settings[4] & 0x20) == 0` in `*(gp+0x74)` (`0x2000C2B8`). |
| **Triggering Source** | TMOS Timer Event `0x0001` (`0xE6E6 -> 0xE3E6`) & Timer Event `0x0004` (`0xE6E6 -> 0xE714`). | Incoming CAN `0x39d` frame (`0x2856 -> 0x2B34(stage)`). |
| **Timing Cadence** | • Mode `0/1/0xF`: `2000 ms + (rand() % 1001) ms` (`2.0..3.0 s`)<br>• Mode `2`: `6000 ms + (rand() % 9001) ms` (`6.0..15.0 s`)<br>• Mode `3`: `15000 ms + (rand() % 15001) ms` (`15.0..30.0 s`)<br>• Hold duration (Timer `4`): `80` TMOS ticks = **`50 ms`**. | **Purely event-driven**: fires immediately when `DAS_handsOnState` reaches the configured stage (`1`, `2`, or `3`), with a **2000 ms** cooldown (`*(0x2000BF00)` via timer `0x2A1A`). |
| **AP & Gear Gating** | In `0x2144(0)` (called on every CAN `0x229` frame at `0x3FBA`):<br>• Requires `*(0x2000C7AD) != 0` (Timer `4` active).<br>• Requires `0x0272() != 0` (vehicle awake) and `*(gp+0x186) == 0`.<br>• If `(settings[3] & 0x0F) == 0x0F`, requires **`0x2AA8() != 0` (AP Active)**. | In `0x2B34(stage)`:<br>• Requires `0x4D14() == 4` (**Drive gear**).<br>• Implicitly gated on AP active because `DAS_handsOnState` (`1..5`) is only non-zero while Autosteer/FSD is engaged. |
| **CAN Output Path** | Sets `*(0x2000C7AD) = 1` for `50 ms`. On the next CAN `0x229` (`0x3FBA -> 0x2144(0)`) or CAN `0x3C2` (`0x222E`), modifies the outgoing scroll-wheel / stalk field and alternates direction (`*(0x2000BEF0) ^= 1`). | Calls `0x2AC0(1)`: if `*(gp+0x186) == 0`, sets `a0=1, a1=1` and jumps directly into `0x2144` (`0x2124`) to emit a scroll-wheel tick immediately. |

---

## Part 2: Offline Multi-Step Automations Without Phone Connection (`0xAB`, `0xAE`, `0xAC`, `0xAA` Tables)

All four automation tables are loaded from CH32V208 DataFlash into SRAM at boot by `0xA9A2` (called from `0x125A` in `main_init`) and evaluated in real time on the MCU without any BLE connection:

| Table Pointer (`.sdata`) | SRAM Address | Size | DataFlash Offset | BLE Write/Read Cmd | Evaluator Function | Entry Format |
|---|---|---|---|---|---|---|
| `*(gp+0x7C)` (`0x2000407C`) | `0x2000C428` | 136 B | `0x7100` | `0xAA` (`0xC34C`) | `0xF450` (actions `0xC8..0xD1`) | 10 slots × 13 bytes (`0..129`) + 6-byte Hall calibration (`130..135`) |
| `*(gp+0x80)` (`0x20004080`) | `0x2000C4B0` | 256 B | `0x7200` | `0xAB` (`0xC1BC`) | `0xE310..0xE354` | 128 slots × 2 bytes: `[trigger_id, action_id]` |
| `*(gp+0x84)` (`0x20004084`) | `0x2000C5B0` | 256 B | `0x7300` | `0xAE` (`0xC232`) | `0xEBFA` (from `0xE364`) | 36 slots × 7 bytes (`252 B`): parameterized / delayed / auto-revert rules |
| `*(gp+0x88)` (`0x20004088`) | `0x2000C6B0` | 256 B | `0x7400` | `0xAC` (`0xC2A8`) | `0xEAEC` (from `0xE372`) | 36 slots × 7 bytes (`252 B`): stateful toggle / conditional rules |

---

### 2.1 Primary `0xAB` 2-Byte Rule Table (`0xE310..0xE354`) & Multi-Action Chaining

#### Disassembly Proof of Sequential Multi-Action Execution (`0xE310..0xE37A`)

```assembly
0x00e310: 0111      c.addi  sp, -0x20
...
0x00e326: 13870108  addi    a4, gp, 0x80        ; a4 = &(*(gp+0x80)) = 0x20004080
0x00e32a: 1043      c.lw    s2, 0(a4)           ; s2 = 0x2000c4b0 (start of 0xAB table)
0x00e332: 2a84      c.mv    s0, a0              ; s0 = incoming trigger_id
0x00e336: 9389090ff addi    s3, s2, 0x100       ; s3 = 0x2000c5b0 (end of 128-entry 0xAB table)
0x00e33a: 83470900  lbu     a5, 0(s2)           ; a5 = entry[i].trigger_id
0x00e33e: 0909      c.addi  s2, 2               ; advance pointer to entry[i+1]
0x00e340: 63940700  bne     s0, a5, 0xe348      ; if trigger_id != s0, skip
0x00e344: 0345f9ff  lbu     a0, -1(s2)          ; a0 = entry[i].action_id
0x00e348: eff03f91  jal     0xd16e              ; execute action_dispatcher(action_id) synchronously!
0x00e34c: e39939fe  bne     s2, s3, 0xe33a      ; loop through ALL 128 pairs without breaking!
0x00e350..0x00e364: ; if s1 == 0, call 0xebfa(s0) for *(gp+0x84) (0xAE table)
0x00e368..0x00e372: ; if s1 == 0, call 0xeaec(s0) for *(gp+0x88) (0xAC table)
```

Because `0xE33A..0xE34C` iterates over all 128 2-byte slots in `0x2000C4B0..0x2000C5AF` and **never breaks on a match**, storing multiple `[trigger_id, action_id]` pairs with the **same `trigger_id`** executes every matching `action_id` sequentially in array order within the same `0xE310` invocation.

#### Subsystem Queueing & Overwrite Behavior During Back-to-Back Execution

When two or more actions fire in the same `0xE310` pass (within microseconds of each other, before the next CAN RX frame or TMOS timer tick), whether both actions take effect depends on whether their target subsystem uses **independent state variables / direct CAN TX** or a **single shared pending-command scalar**:

| Subsystem & Handler | Action IDs (`0xd16e`) | Internal Mechanism | Back-to-Back Behavior in Same `0xE310` Pass |
|---|---|---|---|
| **HVAC / Seat Heaters / Steering Heater / Defrost / Recirc / Camp-Dog-Keep** (`0x7386..0x7514` $\rightarrow$ `0x6ED6`) | `0x1E..0x20`, `0x24..0x26`, `0x3B..0x3C`, `0x42..0x43`, `0x49`, `0x5E..0x62`, `0x83..0x87`, `0x8A..0x8D`, `0x90..0x95`, `0x97..0x98` | Each feature writes its own dedicated RAM byte (`0x2000BFAC..0x2000BFC0`), and `0x6ED6` merges **all** dirty HVAC/heater bytes into the CAN `0x2F3` frame (`0xA6DC`). | **100% Safe to Combine Together**: You can turn on Front-Left Seat Heater (`0x1E`), Front-Right Seat Heater (`0x24`), Steering Wheel Heater (`0x5F`), and Defrost (`0x8C`) on the same trigger. |
| **Seat Motor Direct Move & 10-Slot Seat Memory Recall** (`0xF296`, `0xF450`) | `0x01..0x04`, `0x19..0x1A`, `0xA0..0xCF`, `0xC8..0xD1` | Driver (`seat_id=0`) and Passenger (`seat_id=1`) have separate command bytes (`0x2000C7AC`, `0x2000C7AD`) and separate 12-byte Hall target buffers (`0x2000C77C`, `0x2000C788`), and `0xF1FC` transmits CAN `0x31D` immediately via `0xA6DC`. | **Safe Across Driver + Passenger**: A Driver Seat Memory Preset (`0xC8..0xCC`) and a Passenger Seat Memory Preset (`0xCD..0xD1`) can fire on the same trigger and run their closed-loop Hall controllers in parallel. |
| **Mirrors / Child Locks / Battery Preconditioning / Wiper Speed** (`0x7692`, `0x76BA`, `0x77FC`, `0x7A76`, `0x7A82`) | `0x21..0x22`, `0x67`, `0x7D..0x82`, `0x8E..0x8F` | Each writes a distinct `gp`-relative byte (`0x139(gp)` mirror fold, `0x13A(gp)`/`0x13B(gp)` child locks, `0x142(gp)` preconditioning, `0x144(gp)`/`0x146(gp)` wipers) consumed on CAN `0x273`/`0x229`. | **100% Safe to Combine**: Mirror fold/unfold (`0x21..0x22`), child locks (`0x8E..0x8F`), preconditioning (`0x7D..0x7E`), and wiper speed (`0x7F..0x82`) never overwrite one another. |
| **Headlight / High-Beam Flash & Ambient Lighting** (`0x40AC`, `0x4938`, `0x495A`) | `0x4B`, `0x72`, `0x74..0x7C` | `0x40AC` sets `*(0x2000BF2E) = 0x32` (50-frame counter on CAN `0x229`) and triggers LED animation `0x1436(1)`. `0x495A` writes `0x2000BF45..0x2000BF48`. | **Safe to Combine** with any other subsystem. |
| **Central Lock / Unlock** (`0x4FAC`, `0x5D32`) | `0x1B..0x1D`, `0x3F` | `0x4FAC` writes `*(0x2000BF78)`; `0x5D32` (`0x3F`) calls `0x54FE(0) -> 0x54C2(1)` which writes `*(0x2000BF7A)` (sent on CAN `0x2F3` via `0x5040`). | **Safe to Combine** with closures (`0x05..0x17`) when the screen is awake (`*(0x2000BFC3) != 0`). |
| **Body / Closures / Doors / Trunk / Frunk / Windows / Charge Port** (`0x5B8E`) | `0x05..0x18`, `0x3E`, `0x40..0x41`, `0x44` | Stores `cmd` into a **single scalar byte `*(0x2000BF9C)`** (`0x5BA0`) and then **`*(0x2000BF8A)`** (`0x5546`), which is consumed & zeroed on the **next incoming CAN `0x273` frame** (`0x58BA..0x5920`). Also requires `0x80E0() == 0` (speed == 0). | **Cannot Chain Two `0x5B8E` Actions in `0xAB`**: Firing two `0x5B8E` actions (e.g., Open Frunk `0x05` + Open Trunk `0x06`) in the same `0xE310` pass overwrites `*(0x2000BF9C)`/`*(0x2000BF8A)` so only the **last** `0x5B8E` action executes. *(Solution: place the second `0x5B8E` action in the `0xAE` table with a 1-second delay!)* |
| **Gear / Stalk / Turn Signal / AP Stalk** (`0x33E2`) | `0x28..0x39` | Stores `cmd` into a **single scalar byte `*(0x2000BF2C)`** (`0x3410`), consumed & zeroed on the **next incoming CAN `0x229` frame** (`0x3E16..0x400C`). | **Cannot Chain Two `0x33E2` Actions in `0xAB`**: A second `0x33E2` action in the same `0xE310` pass overwrites `*(0x2000BF2C)`. |
| **Media / Volume Control** (`0x6C90`, `0x6D30`) | `0x50..0x55`, `0x64` | Both call `0x6BB4()` on entry, which **cancels any in-progress media timer (`0x6B4A`)** and resets `*(0x2000BFA0)` before starting the new sequence. | **Cannot Chain Two Media Actions in `0xAB`**: Only the last media/volume action in the same `0xE310` pass survives. |

#### Verified Safe Multi-Step `0xAB` Offline Macro Examples

Because BLE command `0xAB` (`0xC1BC`) writes raw 2-byte `[trigger, action]` pairs into `0x2000C4B0` (when `payload[0] != 0` and `payload[1] != 0xFE`, `0xC1BC` copies `len - 1` bytes starting at `payload[0]` directly into `*(gp+0x80)` and persists to DataFlash `0x7200`), you can program multi-step macros across orthogonal subsystems in a single `0xAB` write:

1. **"Winter Warmup on Brake Press or Door Open"** (Trigger `0x72` = Driver Door Open):
   - Pair 0: `[0x72, 0x3B]` (Driver Seat Heater ON / Max)
   - Pair 1: `[0x72, 0x5F]` (Steering Wheel Heater ON)
   - Pair 2: `[0x72, 0x8C]` (Defrost ON)
   - Pair 3: `[0x72, 0xCA]` (Recall Driver Seat Memory Slot 3)
   - BLE Write Payload: `AB 72 3B 72 5F 72 8C 72 CA 00 00`
2. **"Park & Exit Comfort Macro"** (Trigger `0x46` = Shift into Park):
   - Pair 0: `[0x46, 0x3F]` (Unlock Doors via `0x5D32` $\rightarrow$ CAN `0x2F3`)
   - Pair 1: `[0x46, 0x09]` (Pop Driver Door via `0x5B8E(1)` $\rightarrow$ CAN `0x273`)
   - Pair 2: `[0x46, 0xC8]` (Move Driver Seat to Easy-Entry Preset Slot 1 via `0xF450` $\rightarrow$ CAN `0x31D`)
   - Pair 3: `[0x46, 0x64]` (Mute Media via `0x6C90(2)` $\rightarrow$ CAN `0x3C2`)
   - BLE Write Payload: `AB 46 3F 46 09 46 C8 46 64 00 00`
   *(All four actions use completely independent CAN TX paths and execute in parallel on a single Park transition!)*

---

### 2.2 Secondary (`0xAE`, `*(gp+0x84)`) & Tertiary (`0xAC`, `*(gp+0x88)`) 7-Byte Parameterized Rule Tables

After `0xE310` finishes scanning the 2-byte `0xAB` table, if `s1 == 0` (the trigger was not recursively invoked from `0xEF16`), `0xE310` evaluates:
1. **`0xEBFA(trigger_id)`** (`0xE364`): Scans up to **36 seven-byte rules** (`252` bytes, `0x00..0xFB`) in **`*(gp+0x84)` (`0x2000C5B0`, DataFlash `0x7300`, BLE command `0xAE`)**.
2. **`0xEAEC(trigger_id)`** (`0xE372`): Scans up to **36 seven-byte rules** (`252` bytes, `0x00..0xFB`) in **`*(gp+0x88)` (`0x2000C6B0`, DataFlash `0x7400`, BLE command `0xAC`)**.

#### 2.2.1 Tertiary `0xAC` Table (`0xEAEC`): Stateful Toggle & Conditional Rules

Each 7-byte entry `entry[0..6]` in `*(gp+0x88)` (`0x2000C6B0`) has the following layout (verified from `0xEAEC..0xEBF8` and `0xEF90..0xEFA2`):

| Byte | Name | Meaning in `0xEAEC` (`0xAC` Table) |
|---|---|---|
| `entry[0]` | `trigger_id` | Primary trigger ID (`0x01..0xEE`), matched against incoming `a0` (`0xEB0E`), or `0xFE` in `entry[2]` mode when `entry[0]` is a state-query ID (`1..11`). |
| `entry[1]` | `rule_slot_id` | Rule identifier echoed in BLE `0xF0` notifications (`0xE93E`). |
| `entry[2]` | `eval_mode` | • **`0xFE`**: **Stateless Vehicle-State Conditional Toggle** (`0xEB46..0xEB84`). Queries live vehicle state via `0xEF90(entry[0])`.<br>• **`!= 0xFE`**: **Stateful Alternating Toggle** (`0xEB86..0xEBF6`). Alternates between `entry[4]` and `entry[5]` across successive trigger events. |
| `entry[3]` | `current_state` | Runtime toggle state (`1` = Primary active, `2` = Secondary active). Updated in-place in RAM and reported via `0xF0` BLE notification (`0xE93E`). |
| `entry[4]` | `action_primary` | Action ID (`0xD16E`) executed when transitioning to state `1` (or when `0xEF90(entry[0]) == 0` in `0xFE` mode). |
| `entry[5]` | `action_secondary` | Action ID (`0xD16E`) executed when transitioning to state `2` (or when `0xEF90(entry[0]) != 0` in `0xFE` mode). |
| `entry[6]` | `reserved / flags` | Stored/persisted with the 7-byte slot. |

**`0xEF90` Live Vehicle State Query IDs (used when `entry[2] == 0xFE` in `0xAC` or by `0xE950`)**:

| Query ID (`a0`) | Target Getter Called by `0xEF90` (`0x114CC` jump table) | Returns `1` When: |
|---|---|---|
| `1` | `0x5BD0` (`*(0x2000BF84)`) | Trunk is open |
| `2` | `0x5D22` (`*(0x2000BF85)`) | Frunk is open |
| `3` | `0x5D42` (`0x2000BF86..0x2000BF89` bitmask) | Any door (FL/FR/RL/RR) is open |
| `4` | `0x3212` (`*(0x2000BF0D) == 1`) | Passenger seat adjust / boss mode is enabled |
| `5` | `0x3242` (`*(0x2000BF0F) >= 2`) | Auto turn-signal / lane-change assist is active |
| `6` | `0x751E` (`*(0x2000BFB0) != 0`) | HVAC Recirculation is ON |
| `7` | `0x76A8` (`*(gp+0x139) != 0`) | Side mirrors are folded |
| `8` | `0x7740` (`*(gp+0x13A) != 0`) | Left rear child lock is enabled |
| `9` | `0x774C` (`*(gp+0x13B) != 0`) | Right rear child lock is enabled |
| `10` (`0x0A`) | `0x7808` (`*(gp+0x142) != 0`) | Battery preconditioning is active |
| `11` (`0x0B`) | `0x7A7C` (`*(gp+0x144) != 0`) | Wiper service / washer mode is active |

---

#### 2.2.2 Secondary `0xAE` Table (`0xEBFA`): Precondition-Gated, Delayed, & Auto-Reverting Rules

Each 7-byte entry `entry[0..6]` in `*(gp+0x84)` (`0x2000C5B0`, DataFlash `0x7300`) is a full **offline state machine** evaluated by `0xEBFA..0xED8C` with timer helpers `0xED94` and `0xEDF0`:

| Byte | Name | Meaning in `0xEBFA` (`0xAE` Table) |
|---|---|---|
| `entry[0]` | `trigger_id` | Trigger ID (`0x01..0xEE`) that initiates or advances the rule (`0xEC46`). |
| `entry[1]` | `precondition_id` | Evaluated by **`0xEFA4(entry[1])`** (`0xEC5A`). Rule only fires if `0xEFA4` returns `1`! |
| `entry[2]` | `timing_mode` | • **`0`**: Immediate one-shot (`0xEC78`): executes `entry[4]` immediately via `0xEF16` if `entry[1]` precondition is true.<br>• **`1`**: Delayed execution (`0xEC82`): sets `entry[6] = 1` and starts a timer (`0xEDF0`) for **`entry[3]` seconds**; when the timer expires (`0xEDE2 -> 0xEBFA`), executes `entry[4]`.<br>• **`2`**: Immediate + Timed Auto-Revert (`0xECC2`): executes `entry[4]` immediately, sets `entry[6] = 2`, and starts a timer (`0xED94`) for **`entry[3]` seconds**; when the timer expires (`0xEDD4 -> 0xEBFA`), executes `entry[5]` (revert action) and resets `entry[6] = 0`!<br>• **`3`**: Immediate + Opposite-Trigger Auto-Revert (`0xED12`): executes `entry[4]` immediately and sets `entry[6] = 2`; when the **complementary trigger** (`0xEF2C(entry[0])`, e.g., Door Close `0x73` after Door Open `0x72`) arrives (`0xED52`), executes `entry[5]` and resets `entry[6] = 0`! |
| `entry[3]` | `delay_seconds` | Delay or hold duration in **seconds** (`1..255`), multiplied by `1000 ms` (`0x3E8`) in `0xEDB4` / `0xEE10` and scheduled via `0x110A`. |
| `entry[4]` | `action_primary` | Primary Action ID (`0xD16E` via `0xEF16`). |
| `entry[5]` | `action_revert` | Secondary / Revert Action ID (`0xD16E` via `0xEF16`), executed after `entry[3]` seconds (Mode `2`) or on the opposite trigger (Mode `3`). |
| `entry[6]` | `runtime_state` | Runtime state machine byte (`0` = Idle, `1` = Waiting for Mode `1` delay timer, `2` = Active / Waiting for Mode `2` timer or Mode `3` opposite trigger). |

> **Solving the `0x5B8E` / `0x33E2` Back-to-Back Collision Using `0xAE` Mode `1`:**
> Because `0xAE` Mode `1` delays execution by `entry[3]` seconds via a dedicated timer slot (`0x2000C73C + slot*4`, up to 8 concurrent delayed rules), you can combine any two `0x5B8E` closure commands or `0x33E2` stalk commands on the same trigger by running the first immediately (Mode `0` or in `0xAB`) and the second with `timing_mode = 1, delay_seconds = 1` in `0xAE`!

**`0xEFA4` Precondition Codes (`entry[1]` in `0xAE` Table)**:

| `entry[1]` | Condition Checked by `0xEFA4..0xF1EA` (`0x114FC` jump table) | Meaning |
|---|---|---|
| `0x00` | Always returns `1` (`0xEFB2`) | **No Precondition (Always Allow)** |
| `0x01` | `0x4D14() == 1` (`0xEFC8`) | Vehicle is in **Park (`P`)** |
| `0x02` | `0x4D14() == 2` (`0xEFDC`) | Vehicle is in **Reverse (`R`)** |
| `0x03` | `0x4D14() == 3` (`0xEFEA`) | Vehicle is in **Neutral (`N`)** |
| `0x04` | `0x4D14() == 4` (`0xEFF8`) | Vehicle is in **Drive (`D`)** |
| `0x05` | `0x2AA8() != 0` (`0xF006`) | **Autopilot / Autosteer is Active** |
| `0x06` | `0x5D42() == 0` (`0xF010`) | **All 4 Doors are Closed** |
| `0x07` | `0x5D42() != 0` (`0xF01C`) | **Any Door is Open** |
| `0x08` | `0x7370() != 0` (`0xF026`) | **Driver is Seated / Buckled** (`*(0x2000BFB1) != 0`) |
| `0x09` | `0x2900() == 1` (`0xF030`) | **Passenger is Seated / Buckled** |
| `0x0A` | `0x2900() != 1` (`0xF03E`) | **Passenger Seat is Unoccupied / Unbuckled** |
| `0x0B` | `0x4FE0() == 0` (`0xF04E`) | **Vehicle is Unlocked** (`*(0x2000BF78) == 0`) |
| `0x0C` | `0x4FE0() == 1` (`0xF05A`) | **Vehicle is Locked** |
| `0x0D` | `0x5D22() != 0` (`0xF068`) | **Frunk is Open** |
| `0x0E` | `0x5BD0() != 0` (`0xF072`) | **Trunk is Open** |
| `0x0F` | `0x4162() == 0` (`0xF07C`) | **Exterior Lights are OFF** |
| `0x10` | `0x4162() != 0` (`0xF088`) | **Exterior Lights are ON** |
| `0x11` | `0x7E08() != 0` (`0xF092`) | **Charging / Supercharging is Active** |
| `0x12` | `0x50B0() != 0` (`0xF09C`) | **Sentry Mode is Active** (`*(0x2000BF7B) != 0`) |

**BLE Wire Format for Writing `0xAE` (`0xC232`) and `0xAC` (`0xC2A8`)**:
- **Read Table**: `[0xAE, 0x00]` (returns `0xAE` + 256 bytes via `0xA64E`) or `[0xAC, 0x00]` (returns `0xAC` + 256 bytes via `0xA6A6`).
- **Write Full or Partial Table**: `[0xAE, b0, b1, b2, b3, b4, b5, b6, ...]` (where `b0 != 0` and `b1 != 0xFE`). Copies `len - 1` bytes starting at `payload[0]` into `*(gp+0x84)` (or `*(gp+0x88)` for `0xAC`), persists to DataFlash `0x7300` (or `0x7400`), and sends BLE notification.
- **Delete / Clear Single Rule by `entry[0..1]`**: `[0xAE, trigger_id, 0xFE, ...]` (`0xAF1A` / `0xAEAC`): finds the 7-byte slot matching `trigger_id` and compacts the remaining 7-byte entries.

---

### 2.3 10-Slot Seat Memory Table (`0xAA` Handler `0xC34C` & Recall Controller `0xF450`)

#### SRAM & DataFlash Layout (`*(gp+0x7C) = 0x2000C428`, DataFlash `0x7100`, 136 Bytes)

- **Bytes `0..129` (10 slots × 13 bytes)**:
  - **Slots `0..4` (1-based `slot_id = 1..5`)**: **Driver Seat Memory Presets 1..5** (recalled by rule actions **`0xC8..0xCC`**).
  - **Slots `5..9` (1-based `slot_id = 6..10`)**: **Passenger Seat Memory Presets 1..5** (recalled by rule actions **`0xCD..0xD1`**).
  - Each 13-byte slot at `0x2000C428 + (slot_id - 1) * 13` has the layout:
    - `slot[0]` (`uint8_t`): **`enable_flag`** (`0x01` = Preset valid/enabled, `0x00` = Empty/disabled).
    - `slot[1..12]` (`int16_t[6]`, little-endian): **6 signed 16-bit Hall/position targets** (`axis[0..5]`):
      - `axis[0]` (`slot[1..2]`): Fore/Aft track position
      - `axis[1]` (`slot[3..4]`): Seat height / rear lift position
      - `axis[2]` (`slot[5..6]`): Seat cushion tilt position
      - `axis[3]` (`slot[7..8]`): Backrest recline angle
      - `axis[4]` (`slot[9..10]`): Headrest / lumbar axis 1
      - `axis[5]` (`slot[11..12]`): Lumbar axis 2
- **Bytes `130..135` (`0x2000C4AA..0x2000C4AF`)**: 6 calibration/limit bytes initialized to `0xFF` on first boot (`0xA9F2`).

#### BLE Command `0xAA` (`0xC34C..0xC3C8`) Exact Payload Format

Disassembly of `0xC34C` (linked `0x0001434C`) reveals three operations on BLE command `0xAA`:

1. **Read All 10 Seat Memory Presets (`[0xAA, 0x00]`)**:
   - `payload[0] == 0x00` (`0xC350: lbu a4, 0(s0); c.beqz a4, 0xc3c4`):
   - Calls `0xA620(conn_handle)`, which sends a **131-byte BLE notification**: `[0xAA]` followed by the 130-byte seat preset array (`0x2000C428..0x2000C4A9`, 10 × 13 bytes).

2. **Write / Save a Seat Memory Preset (`15 bytes` total including `0xAA` opcode)**:
   - Requires `1 <= payload[0] <= 10` (`addi a5, a4, -1; andi a5, 0xff; li a3, 9; bltu a3, a5, exit`), `payload[1] != 0`, and `payload_len == 14` (`0xC366: li a5, 0xe; bne s2, a5, exit`):
   ```
   Byte:  [0xAA] [slot] [en] [ax0_L] [ax0_H] [ax1_L] [ax1_H] [ax2_L] [ax2_H] [ax3_L] [ax3_H] [ax4_L] [ax4_H] [ax5_L] [ax5_H]
   Index:  cmd    p[0]  p[1]  p[2]    p[3]    p[4]    p[5]    p[6]    p[7]    p[8]    p[9]    p[10]   p[11]   p[12]   p[13]
   ```
   - `0xC370..0xC392`: Computes destination `dst = *(gp+0x7C) + (slot - 1) * 13`, copies `13` bytes from `&payload[1]` (`p[1]..p[13]`) into `dst[0..12]`, calls `0xACA0()` to persist all 136 bytes to DataFlash `0x7100`, and calls `0xA636()` to broadcast the updated 131-byte `0xAA` table over BLE.

3. **Delete / Disable a Seat Memory Preset (`[0xAA, slot_1_to_10, 0x00]`)**:
   - When `1 <= payload[0] <= 10` and `payload[1] == 0x00` (`0xC362: c.beqz a5, 0xc396`):
   - Zeroes all 13 bytes of `*(gp+0x7C) + (slot - 1) * 13` via `memset(dst, 0, 13)`, calls `0xACA0()` to persist to DataFlash `0x7100`, and broadcasts the updated `0xAA` table via `0xA636()`.

#### Closed-Loop Offline Seat Recall (`0xF450..0xF760`)

When a rule triggers action **`0xC8..0xCC`** (`0xD16E` passes `slot_id = 1..5` to `0xF450`) or **`0xCD..0xD1`** (`slot_id = 6..10` to `0xF450`):
1. `0xF450` verifies `*(gp+0x188) <= 4` (Model 3/Y seat controller), checks `slot[0] != 0` (`enable_flag`), and copies the 12-byte target array (`slot[1..12]`) into:
   - **`0x2000C77C..0x2000C787`** (`s2 + 0x10`) for Driver slots `1..5`, setting `*(0x2000C7A8) = 1` and arming the **100 ms (`0x64`)** closed-loop timer **`0xF568`**.
   - **`0x2000C788..0x2000C793`** (`s2 + 0x1C`) for Passenger slots `6..10`, setting `*(0x2000C7A9) = 1` and arming the **100 ms (`0x64`)** closed-loop timer **`0xF660`**.
2. Every 100 ms, `0xF568` (Driver) / `0xF660` (Passenger) compares live seat Hall-sensor positions from CAN against the target `int16_t` axes (`0xF32A`), builds the 8-bit motor direction bitmask (`Fore/Aft`, `Lift`, `Tilt`, `Recline`), sends CAN `0x31D` via `0xF296(seat_id, mask, 2)`, and stops individual axes as soon as they enter the deadband (`|target - current| <= 2`).

---

## Part 3: Verified Binary Patch — `unlock_steering_triggers_all_gears_0x8100`

### 3.1 Patch Specification

- **Patch ID**: `unlock_steering_triggers_all_gears_0x8100`
- **Category**: `automation`
- **Target Function**: `0x0080EC..0x00811C` (linked `0x000100EC..0x0001011C`, flash `0x080100EC`)
- **Payload Offset**: `0x008100` (Page `32`, intra-page offset `0x100`, transport offset `0x008142`)

| State | Payload Offset | Bytes (Hex) | RISC-V Disassembly | Behavior |
|---|---|---|---|---|
| **Stock** | `0x008100` | `631bf500` | `bne a0, a5, 0x16` (`-> 0x008116`) | Drops steering-angle triggers `0xAA..0xB0` unless `0x4D14() == 4` (Drive gear). |
| **Patched** | `0x008100` | `13000000` | `nop` (`addi zero, zero, 0`) | Allows `0xAA..0xB0` in Park (`1`), Reverse (`2`), Neutral (`3`), and Drive (`4`) whenever vehicle is awake (`0x0272() != 0`) and Autopilot is inactive (`0x2AA8() == 0`). |

### 3.2 Usage with `tools/firmware_patcher.py`

```bash
# Inspect stock or patched firmware image
.venv-re/bin/python tools/firmware_patcher.py inspect latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin

# Apply unlock_steering_triggers_all_gears_0x8100 standalone or with the community bundle
.venv-re/bin/python tools/firmware_patcher.py patch \
  --in latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin \
  --out work/runtime.patched.bin \
  --enable ignore_server_deauth_0xae,bypass_auth_check_0x1380,enable_0xa6_disable_cmd,pulse_timing_fast_1500ms,pulse_hold_short_25ms,custom_fw_version_tag,unlock_steering_triggers_all_gears_0x8100
```
