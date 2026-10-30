# Firmware Session Notes

Date: 2026-10-29

## Latest Session Summary (2026-10-29)

1. **Invalid OTA Payload Analysis (`poisoned-ota-2026-10-28-535C62E239E339E31475FB10/`)**:
   - Captured and archived the non-executable payload served by `https://www.iffrc.com/ffkj/user/ble.php` (`fun=update`) on 2026-10-28, which caused `TSL-BOOT` (`boot.payload.bin @ 0x001642`, linked `0x002642`) to remain in recovery mode because `*(uint8_t*)0x08008000 != 0x6F`.
2. **Community Firmware Patcher & Verified Catalog (`tools/firmware_patcher.py`, `analysis/patch_catalog.json`, `COMMUNITY_FIRMWARE_MODS.md`)**:
   - Built a deterministic Python + Capstone patcher and validator with 10 verified binary patches (`ignore_server_deauth_0xae`, `bypass_auth_check_0x1380`, `enable_0xa6_disable_cmd`, `pulse_timing_fast_1500ms`, `pulse_timing_gentle_1000ms`, `pulse_hold_short_25ms`, `custom_fw_version_tag`, `unlock_steering_triggers_all_gears_0x8100`, `gate_media_pulse_on_ap_0x2242`, and `fix_hands_on_reminder_detection`) plus custom FSD keycode remapping and 11 unit/disassembly tests (`tools/test_firmware_patcher.py`).
3. **Complete Telemetry, CAN `0x39d`/`0x129`/`0x3FD`/`0x3DF` AP/Hands-On Detection & Offline Multi-Step Automation Disassembly (`TELEMETRY_AND_RULE_ENGINE_DEEP_DIVE.md`, `OFFLINE_AUTOMATIONS_AND_AP_DETECTION.md`)**:
   - Mapped all 33 bytes of `0xB0` (`0xAE26`), all 75 bytes of `0xA0` (`0xAF6C`), CAN `0x39d` (`ID39DDAS_status` @ `0x2856..0x2D38`: `0x4E/0x4F` AP Engaged/Disengaged, `0xA8/0xA9` Hands-On Warning Active/Cleared + `0x2B34` reactive handler, `0x50/0x51` Takeover Alert, `0x96/0x97` Activation Failure), CAN `0x129` (`ID129SteeringAngle` @ `0x80EC..0x8230`: `0xAA..0xB0`), Bus 0 `0xC0` CAN sniffer handlers (`0x00C2EE..0x00C4F8`, `0x00A5F8..0x00A772`), and the 4 offline automation/memory tables (`0xAB` @ `0xE310`, `0xAE` @ `0xEBFA`, `0xAC` @ `0xEAEC`, and `0xAA` 10-slot closed-loop seat memory @ `0xC34C`/`0xF450`).

---

## Historical Session Notes (2026-07-17)

## Current objective

Recover enough of the archived TSL6 runtime, boot, and resident interfaces to
edit an existing update or implement a compatible replacement without losing
hardware capabilities. Static analysis has advanced substantially, but it does
not yet justify producing or flashing a modified image.

## Verified this session

- Transport pages are 1026 bytes: a two-byte big-endian index plus 1024
  payload bytes. Base-zero analysis offsets refer to the stripped payload.
- Runtime is linked at `0x00008000`, stored at flash alias `0x08008000`, and
  accepted in a `0x18000`-byte slot. Boot is linked at `0x00001000`, stored at
  `0x08001000`, and accepted in a `0x7000`-byte slot.
- Both startup paths resolve `gp=0x20004000`, `sp=0x20010000`, and a resident
  BLE library at `0x00040000` with a function jump table at `0x00040034`.
  These addresses are distinct from the CH32V peripheral region at
  `0x40000000`.
- Runtime AUIPC RAM references include the `0x8000` linked base. The full
  scanner reports candidates across SRAM; ten telemetry cache addresses are
  asserted as landmarks between `0x2000be5c` and `0x2000bf86`, including gear
  at `0x2000bf60` and inverter power at `0x2000be5c`.
- The embedded `CH32V20x_BLE_LIB_V1.3` string matches OpenWCH commit
  `64be9554615df522899579633530fd234d685682`. Its header names confirmed ABI
  slots `tmos_memcmp` (`0x4003c`), `tmos_isbufset` (`0x40040`), `tmos_memset`
  (`0x40048`), `tmos_memcpy` (`0x4004c`), `tmos_set_event` (`0x40050`),
  `tmos_msg_deallocate` (`0x40068`), `tmos_msg_allocate` (`0x40070`), and
  `GAPRole_TerminateLink` (`0x4017c`).
- `tmos_memcmp` uses the library's Boolean convention (`TRUE` means equal),
  correcting the earlier interpretation of the HID-name comparison branches.
- Runtime payload `0x0d02` builds/enqueues BLE frames. Payload `0x110a` is a
  15-slot delayed-callback scheduler using 12-byte entries at `0x2000be28`; it
  converts milliseconds to 625-microsecond ticks.
- The update writers are complementary. Runtime worker `0x1bc8` accepts start
  target `0` and writes boot pages `0..27` at `0x08001000`. Boot worker
  `0x121c` accepts target `1` and writes runtime pages `0..95` at
  `0x08008000`. Runtime prepare target `1` schedules callbacks after 200 ms and
  400 ms to transfer runtime-target updating toward boot mode.
- Both images contain local flash helpers using controller base `0x40022000`.
  Each 1 KiB transport payload is erased and programmed as four 256-byte fast-
  flash operations. RCC `CFGR0` at `0x40021004` temporarily selects HPRE
  divide-by-2 or divide-by-4; it is not a flash control register. No timeout or
  flash error-bit handling has been found.
- Action 139 reaches payload `0x3a30`, which stores `12` at `0x2000bf2d`.
  Branch `0x3cdc` decrements the byte and changes bits 6:5 of the current object
  whenever it is nonzero. Cadence, release semantics, and vehicle-side effect
  remain unproven.
- The primary shortcut table still stores only trigger/action pairs; it cannot
  directly represent a delayed multi-step macro.

Generator assertions bind startup, embedded BLE-library version, updater,
copy-slot, page arithmetic, and flash-helper claims to the archived image
bytes. Regeneration recovered 357 candidate RAM addresses (10 telemetry-mapped)
and 163 gp-relative state offsets.

## Verification and review status

- Canonical generation completed with 419 runtime functions, 84 boot functions,
  34 CAN IDs, 33 rule-trigger sites, 474 runtime symbols (87 named), and 85 boot
  symbols (8 named).
- A fresh deterministic regeneration of every generated artifact compared
  byte-for-byte equal with the working-tree outputs. Tool compilation, JSON
  parsing, artifact invariants, local Markdown links/anchors, payload hashes,
  startup `gp`/`sp` recovery, linked-target annotations, and `git diff --check`
  also passed.
- An independent read-only review completed. Its findings were incorporated,
  including the corrected resident-ABI base/table distinction, Boolean
  `tmos_memcmp` semantics, and removal of unsupported `0xF0` persistence and
  demotion of peer/bond semantics to Correlated.

## Open safety blockers

- Obtain a physical full-flash dump and option-byte/protection capture before
  modifying anything.
- Identify the exact CH32V20x variant and confirm the flash-alias/remap mechanism
  from hardware state rather than static inference.
- Establish and test WCH-Link recovery on a sacrificial module, including
  interrupted-update and invalid-runtime behavior.
- Confirm image/version/integrity rules outside the downloaded payloads.
- Map the remaining resident ABI, interrupt/vector, clock, BLE, CAN, watchdog,
  and nonvolatile-storage contracts needed for a compatible rewrite.
- Confirm action and telemetry meanings with passive traces and controlled
  vehicle-side validation; catalog labels alone are not proof.

Never issue BLE update commands (`0x55`, `0x53`, `0x57`, `0x52`, `0x45`) as a
backup or analysis technique. Readback `0x52` is part of update mode, not a
proven full-flash dump path.

## Next concrete research step

The current next step is to obtain a read-only physical full-flash dump plus
option-byte/protection snapshot and compare its `0x08001000` boot and
`0x08008000` runtime regions byte-for-byte with the stripped payloads. That
single comparison can validate slot placement, reveal resident contents near
the `0x00040000` ABI view, and constrain the still-unknown remap mechanism
without sending update commands.
