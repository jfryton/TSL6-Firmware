# TSL6 Bootloader (boot.bin) Internals

Component-level documentation of the **boot** image, recovered by static
analysis. The bootloader is the component that actually erases and programs
flash, so it is the most safety-critical part of the system.

All offsets are payload offsets (stripped image, base 0). Machine-readable
companions: [analysis/boot.json](analysis/boot.json) and
[analysis/boot_functions.json](analysis/boot_functions.json).

> Safety: the commands and addresses documented here can brick the module. This
> document exists to make the update path *understandable and auditable*, not to
> encourage flashing. See the repository README safety notice.

## 1. Identity and Startup

| Item | Value | Status |
|---|---|---|
| Image string | `TSL6-BOOT` | Confirmed |
| BLE library | `CH32V20x_BLE_LIB_V1.3` | Confirmed |
| Payload size | 12,288 bytes (12 KiB) | Confirmed |
| Reset jump | `0x0000 -> 0x1c28` | Confirmed |
| `gp` | `0x20003000` | Confirmed |
| `sp` | `0x2000f000` | Confirmed |

Startup at `0x1c28` mirrors the runtime: it copies `.data` (`gp .. gp+0x88`)
from flash to RAM, zeroes `.bss`, programs the machine CSRs, and enters the
bootloader main loop. 84 functions are recovered (`analysis/boot_functions.json`).

## 2. Update Command Dispatcher

Entry: `0x121c`. The bootloader receives the same BLE update frames as the
runtime relay and dispatches on the command byte:

| Cmd | Purpose | Status |
|---:|---|---|
| `0x55` | Prepare/select update target. Clears the in-progress flag at `gp+0xaf` and validates the requested target via `0xc9a`. | Confirmed |
| `0x53` | Begin selected target. Sets the in-progress flag `gp+0xaf` and selects the boot(`0`)/runtime(`1`) slot. | Confirmed |
| `0x57` | Write one 1026-byte transport page (see section 3). | Confirmed |
| `0x45` | Finalize and report completion. | Confirmed |

The in-progress flag at `gp+0xaf` gates page writes: `0x57` is rejected unless a
prior `0x53` set it. This is the state machine that makes the page-read/verify
operations part of update mode rather than a standalone backup path.

## 3. Flash Write / Erase / Verify Flow

The `0x57` write-page handler is the core of the updater (Confirmed):

1. **Size check** - the page must be `0x402` (1026) bytes: the 2-byte
   big-endian page index plus 1024 bytes of payload.
2. **Destination** - the page index is parsed from the first two bytes and used
   to compute the flash destination address (page * 0x400 within the target
   slot region).
3. **Align + erase** - the destination is page-aligned and erased through a
   resident flash-erase function pointer at `0x4000004c`, with erase
   granularity `0x400` (1 KiB).
4. **Program** - the 1024-byte payload is written in `0x100`-byte (256) chunks
   via the flash programming routine at `0x110c`.
5. **Verify** - the handler reads back the programmed region and compares it
   word-by-word against the source buffer; any mismatch aborts the page and
   reports failure.

### Flash controller

The programmer at `0x110c` accesses the CH32V20x flash programming region. It
detects a flash size/variant by comparing a size word at `gp+0x80` against
`0x8954400` and selects a control bit (`0x80` vs `0x90`), which it
read-modify-writes into the control register at `0x40021004` before performing
the unlock/program/lock sequence. (The exact register field semantics are not
yet fully decoded; the address and the OR'd values are Confirmed.)

## 4. Why This Matters for a Rewrite

This is the previously-Unknown, safety-critical mapping the clean-room spec
flagged. With it documented:

- A replacement updater can reproduce the exact page transport, erase
  granularity, and verify behavior expected by the deployed module.
- The boot-slot selection (`0x53` target `0`/`1`) and the in-progress flag at
  `gp+0xaf` define the minimum state machine a compatible bootloader must keep.

Still **Unknown** and required before any flashing:

- Absolute flash base addresses for the boot and runtime slots (the resident
  erase/program pointers hide them; a physical dump is needed to confirm).
- Option bytes, read/write protection, and brown-out behavior during erase.
- Whether a failed runtime write leaves the bootloader recoverable over BLE.

See [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) section 4 for the transport-level
contract and [FIRMWARE_INTERNALS.md](FIRMWARE_INTERNALS.md) section 8 for the
runtime relay side.
