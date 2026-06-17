# Firmware Session Notes

Date: 2026-06-12

Current question: whether a firmware-only custom action can perform:

```text
wait 0.5 s
left scroll hold
wait 0.5 s
left scroll select
```

Short answer: not safely yet.

Useful local artifacts:

- Runtime image:
  `/Users/jeff/tsl-firmware-downloads/535C62E239E339E31475FB10-2026-06-11/runtime/runtime.bin`
- Boot image:
  `/Users/jeff/tsl-firmware-downloads/535C62E239E339E31475FB10-2026-06-11/boot/boot.bin`
- Analyzer:
  `/Users/jeff/tsl-android/tools/analyze_firmware.py`
- Capstone venv:
  `/Users/jeff/tsl-android/tools/.venv-re`

Key findings:

- Firmware is RISC-V/RVC for WCH CH32V20x BLE.
- Downloaded images use 1026-byte transport pages: two-byte page index plus
  1024-byte payload.
- Stripped runtime payload is 72 KiB; stripped boot payload is 12 KiB.
- Main BLE dispatcher begins around payload offset `0xBDEA`.
- Shortcut rule read/write command `0xAB` is confirmed.
- Rule engine around payload `0xE310` scans 256 bytes as trigger/action pairs.
- Each matched rule calls the action dispatcher with exactly one action byte.
- There is no rule-level field for delay, step count, or macro data.
- Action dispatcher begins around payload `0xD16E`.
- Command `0xBB` executes/tests one action byte via that dispatcher.
- Command `0xA2` around `0xC5A0` likely handles momentary button input values
  1-5, but its primitive meanings still need tracing.

Catalog distinction:

- Trigger 139 means speed 5-10.
- Action 139 means left scroll middle-button hold.
- Do not use one global label map for both namespaces.

Corrected action mapping:

- Removing transport page indices resolves the prior jump-table ambiguity.
- Action table base is payload `0x11710`.
- Action 139 resolves to payload handler `0xDB74`.
- It tail-calls payload `0x3A30`, which writes `0x0C` to a RAM state byte.
- The consumer and timing semantics of that state byte remain unknown.

Do not flash modified firmware until:

- Full physical flash backup and WCH-Link recovery are available.
- A spare TSL6 module is available for first tests.
- Action 139 side effect is confirmed.
- Press/release/select primitives are confirmed.
- A non-blocking timer/work-queue primitive is identified.
- Firmware image integrity checks are understood.
