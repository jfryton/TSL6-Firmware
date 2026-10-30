# TSL6 Boot Image (`boot.bin`) Internals

Component-level documentation of the **boot** image, recovered by static
analysis. This image contains the updater that writes the runtime slot; the
runtime image contains a complementary updater that writes the boot slot. Both
paths are safety-critical.

All analysis addresses are payload offsets unless explicitly described as
linked or flash-alias addresses. Machine-readable companions:
[analysis/boot.json](analysis/boot.json) and
[analysis/boot_functions.json](analysis/boot_functions.json).

> Safety: the commands and addresses documented here can brick the module. This
> document exists to make the update path understandable and auditable, not to
> provide flashing instructions. See the repository README safety notice.

## 1. Identity and Startup

| Item | Value | Status |
|---|---|---|
| Image string | `TSL6-BOOT` | Confirmed |
| BLE library | `CH32V20x_BLE_LIB_V1.3` | Confirmed |
| Downloaded payload | 12,288 bytes (`0x3000`) | Confirmed |
| Linked code base | `0x00001000` | Confirmed |
| Flash alias used for this slot | `0x08001000` | Confirmed in the runtime updater |
| Statically accepted boot-slot size | `0x7000` (28 KiB) | Confirmed |
| Reset jump | payload `0x0000 -> 0x1c28` | Confirmed |
| `gp` | `0x20004000` | Confirmed |
| `sp` | `0x20010000` | Confirmed |
| Resident BLE library / jump table | `0x00040000` / `0x00040034` | Confirmed; backing Unknown |
| Peripheral region | `0x40000000` | Confirmed |

Startup at payload `0x1c28` copies `.data` (`gp .. gp+0x88`) from flash to
RAM, zeroes `.bss`, programs the machine CSRs, and transfers through resident
code around `0x00040000`. The low linked base, the `0x08001000` flash alias,
and the resident execution target are distinct address views; the exact remap
mechanism remains Unknown. 84 functions are recovered in
`analysis/boot_functions.json`.

## 2. Runtime-Slot Update Dispatcher

Entry: payload `0x121c`. This worker accepts these BLE update commands:

| Cmd | Purpose | Status |
|---:|---|---|
| `0x55` | Prepare: clear the in-progress flag at `gp+0xaf` and validate the trailing 14-byte value via `0xc9a`. | Confirmed |
| `0x53` | Begin the update only when the target byte is `1` (runtime); set `gp+0xaf`. | Confirmed |
| `0x57` | Write one 1026-byte transport page while `gp+0xaf` is set. | Confirmed |
| `0x45` | Finalize and report completion while an update is in progress. | Confirmed |

The target gate is not a general boot/runtime selector in this image: start
target `1` is accepted and other target values are rejected. The complementary
runtime worker accepts start target `0` and writes this boot slot (section 4).

## 3. Flash Write, Erase, and Verify Flow

The `0x57` handler performs the following byte-backed flow:

1. Require exactly `0x402` (1026) bytes: a two-byte big-endian page index and
   1024 payload bytes.
2. Compute `destination = 0x08008000 + page_index * 0x400` and reject indices
   outside `0..95`. This is a statically accepted `0x18000`-byte runtime slot.
3. If `payload+2` is not word-aligned, copy the 1024 bytes into an aligned
   buffer through resident slot `0x4004c`, `tmos_memcpy`. It is not
   a flash-erase entry.
4. Invoke local wrapper `0x110c` at offsets `0`, `0x100`, `0x200`, and `0x300`.
   Each invocation fast-erases and programs 256 bytes, so one 1 KiB transport
   page requires four erase/program cycles.
5. Compare all 1024 programmed bytes against the source word-by-word; a
   mismatch rejects the page.

The slot limit is an updater bounds check, not proof that all accepted bytes
belong to the archived 72 KiB runtime payload.

### Flash controller and clock setup

The flash operations used by `0x110c` are local to this image and access the
CH32V flash controller at `0x40022000`:

| Helper | Role |
|---:|---|
| `0x2032` | clear flash status |
| `0x203a` | unlock fast programming |
| `0x2058` | lock fast programming |
| `0x2066` | fast-erase 256 bytes |
| `0x2094` | fast-program 256 bytes |

The wrapper compares the clock value at `gp+0x80` with 144 MHz. It temporarily
ORs `0x80` (HPRE divide-by-2) or `0x90` (HPRE divide-by-4) into RCC `CFGR0` at
`0x40021004`, then clears those bits. This register is RCC clock configuration,
not flash control; the names and bit meanings agree with the official WCH
CH32V20x headers.

The erase/program helpers poll flash busy state without a timeout. They do not
test the documented program-error, write-protection-error, or end-of-operation
bits, and the wrapper has no status return. Read-back comparison catches data
mismatch after a completed call, but it does not make a hung or interrupted
flash operation recoverable.

## 4. Complementary Runtime Writer

The runtime image is not merely a relay. Its worker at payload `0x1bc8` accepts
start target `0`, writes the boot slot at `0x08001000`, accepts page indices
`0..27` (`0x7000` bytes), and performs the same four 256-byte local
erase/program operations plus 1 KiB read-back comparison. Its local flash
helper copies are at `0x10010`, `0x10018`, `0x10036`, `0x10044`, and `0x10072`.

Runtime prepare target `1` instead schedules callbacks at `0xe1a` after 200 ms
and `0x1e16` after 400 ms, transferring toward the boot-mode path that can
write the runtime slot. The scheduler is runtime function `0x110a`.

## 5. Safety Boundary for a Rewrite

Static analysis now establishes both updater destinations, their accepted slot
bounds, local flash-controller routines, and read-back behavior. It does not
establish that modifying either slot is safe.

Still Unknown and required before any flashing:

- A physical flash dump confirming the aliases, complete resident contents,
  and what backs the execution view around `0x00040000`.
- The exact flash-remap/vector mechanism and boot-selection state.
- Option bytes, read/write protection, image validation, and reset/brown-out
  behavior during erase or program.
- Rollback behavior and whether a failed runtime or boot write leaves a BLE or
  debug recovery route.
- Recovery testing on sacrificial hardware and a verified restore procedure.

See [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) section 4 for the transport-level
contract and [FIRMWARE_INTERNALS.md](FIRMWARE_INTERNALS.md) section 8 for both
update workers.
