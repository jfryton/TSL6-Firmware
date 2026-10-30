# TSL6 automatic media / volume scheduler

This note maps the persistent automatic volume and media scheduler settings used by the original Mini
App. It describes the recovered runtime only; no firmware patching or update
commands are involved. Physical validation on each firmware/vehicle variant is
still required.

## Settings record

`0xA0` returns the complete 76-byte TSL6 status/settings record. `0xA3` accepts
only a complete 76-byte replacement, validates its existing credential field,
and returns the saved record. The status-page master switch is byte 19 bit 0;
`0xA1 01`/`0xA1 00` changes that master and `0xA6 01` selects AP/FSD-controlled
activation. `0xA6 00` is a no-op in this image.

The media scheduler fields below are in the first settings block copied by the
`0xA3` handler (`0xBEAE`). Byte offsets are in the returned record, not the RAM
structure. Reserved bits and identity/VIN fields must be preserved by a complete
read-modify-write; clients must not construct a zero-filled settings record.

| Offset | Bits | Meaning | Confidence |
|---:|---:|---|---|
| 19 | 0 | Scheduler master enable | Confirmed Mini App / runtime |
| 28 | 3 | Media scheduler enable (`0x25B0` also checks other settings) | Confirmed |
| 28 | 0 | Adds 0–2 seconds of random delay to the selected pulse timing | Confirmed |
| 28 | 6–7 | Mode: 0 volume keycodes 1/3; 1 AP-speed keycodes 9/11; 2 alternate; 3 random. Left/right wheel association comes from the recovered product controls, not instruction names. | Confirmed structure / correlated labels |
| 31 | 7–5 | Preserve: other packed settings | Not volume fields |
| 31 | 3–4 | Pulse timing: 0: 2 s; 1: 2–3 s; 2: 3–5 s; 3: 5–10 s | Confirmed |
| 31 | 0–2 | Periodic interval code 0–7: off, 10, 20, … 70 minutes | Confirmed |
| 33 | 0–1 | Direction: 0 up, 1 down, 2 alternating, 3 random | Confirmed structure / correlated labels |
| 33 | 2–7 | Other settings; preserve | Not volume fields |
| 28 | 1–2, 4–5 | Other settings; preserve | Not volume fields |

The firmware scheduler at `0xE4E4` sets/cancels the native event. The timing
worker at `0xE3E6` builds the pulse timing; `0xE5C2` calls the direction worker
at `0x222E`. The wheel/mode bits choose volume keycodes `1`/`3` or AP-speed
keycodes `9`/`11`. Direction byte 33 selects up/down, an alternating countdown,
or a random direction. These are distinct settings: wheel/mode must not be
mislabeled as volume direction, and a left/right selection is not itself a
volume up/down selection. The Android client does not generate these actions;
it writes them once to the module, whose scheduler continues independently.

With timer code zero, the native timing worker handles AP/FSD transitions rather
than the long periodic interval. Codes 1–7 schedule `code * 600000` milliseconds,
so a nonzero periodic timer can act while AP/FSD is inactive and without Android.
This is separate from the phone's fresh telemetry/hands-on checks and is a likely
explanation for volume commands after FSD turns off. Selecting timer zero is
required for AP/FSD-only activation; the firmware's master and AP/FSD mode also
remain relevant. The original Mini App page that exposed these controls is absent
from the recovered chunks, so exact original labels/help text are not claimed here.

## Safe client behavior

1. Require a connected, authenticated TSL6 and a complete current 76-byte record.
2. Let the user explicitly read/refresh before editing; never silently replace
   an unread record with defaults.
3. Change only the documented bits, retaining every other byte and reserved bit.
4. Send the full record once with `0xA3`; do not use update commands.
5. Accept success only when the returned `0xA3` record decodes to the requested
   values. Handle a mismatch, timeout, disconnect and another in-flight
   customization as an unconfirmed operation and ask for a fresh readback.
6. Keep this persistent firmware feature distinct from a phone-generated
   balanced volume pulse and from trigger/action rules in the `0xAB` table.

## Disassembly landmarks

- `0xBEAE` — complete settings-record write handler.
- `0xC510` — immediate `0xA1` master command.
- `0xBFB4` — `0xA6` AP/FSD automatic-mode selection.
- `0xE4E4` — scheduler enable/cancel and long-period selection.
- `0xE3E6` — media timing and variation calculation.
- `0xE57E` — media worker / direction selection entry.
- `0x222E`, `0x2144` — direction state and volume keycode choice.
- `0x33E2` — media keycode primitive; 1 = volume up, 3 = volume down.
