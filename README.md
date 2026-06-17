# TSL6 Firmware Archive and Reverse Engineering

Recovered firmware artifacts and reverse-engineering notes for the abandoned
TSL6 electronic module (WCH CH32V20x RISC-V BLE). This repository preserves the
firmware images, manifests, structural maps, and analysis needed to maintain,
document, and (eventually) reimplement compatible TSL hardware.

It was extracted from the firmware work originally kept inside the
[TSL-WeChat-MiniApp-Extracted](https://github.com/jfryton/TSL-WeChat-MiniApp-Extracted)
repository so that firmware analysis can evolve independently.

## Related Repositories

- [TSL-Cmd](https://github.com/jfryton/TSL-Cmd): native Android controller and
  driving dashboard for compatible TSL modules. This firmware repo is one of its
  reference sources.
- [TSL-WeChat-MiniApp-Extracted](https://github.com/jfryton/TSL-WeChat-MiniApp-Extracted):
  decrypted/unpacked WeChat Mini Program reference source. The BLE protocol and
  firmware-update flow documented here were recovered from that application.

## Safety Boundary

The firmware files here were downloaded over HTTPS only. No BLE firmware/update
commands were sent to the TSL6 module during download.

Do not treat this archive as a flashing tool. The Mini App updater enters
firmware update mode using BLE commands `0x55` and `0x53`, writes pages with
`0x57`, may read pages back with `0x52`, and finalizes with `0x45`. Those
commands can affect module boot state and should not be used for backup or
experimentation without vendor documentation or sacrificial hardware.

## Archived Build

Path:

```text
latest-tsl6-535C62E239E339E31475FB10/
```

Downloaded for module:

```text
ID:  535C62E239E339E31475FB10
VIN: 5YJ3E1ET7RF889921
MAC: 5C:53:10:FB:75:14
Installed boot version observed by app:    V1.2.00
Installed runtime version observed by app: V1.0.00
```

Archived artifacts:

```text
boot/boot.bin
boot/boot.manifest.json
boot/boot.map.json
runtime/runtime.bin
runtime/runtime.manifest.json
runtime/runtime.map.json
```

The manifest files record page count, page size, byte count, and SHA-256.
The map files record both transport and stripped-payload structure.

## Documentation

- [FIRMWARE_INTERNALS.md](FIRMWARE_INTERNALS.md): component-level map of the
  runtime firmware (memory map, command dispatcher, action table, rule engine,
  BLE TX path, telemetry packing). Start here to understand the firmware.
- [BOOTLOADER.md](BOOTLOADER.md): the boot image and the flash erase/program/
  verify update flow (safety-critical).
- [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md): compatibility requirements for an
  independent replacement firmware.
- [ANALYSIS_WORKFLOW.md](ANALYSIS_WORKFLOW.md): reproducible extraction and
  disassembly process.
- [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md): chronological findings and
  detailed evidence.
- [SESSION_NOTES.md](SESSION_NOTES.md): working notes from analysis sessions.

## Tooling and Generated Analysis

- [tools/](tools/): reproducible RISC-V analysis tooling (payload extraction,
  RV32+RVC disassembler, dispatcher/action-table decoders, artifact generator).
  Only dependency is Capstone. See [tools/README.md](tools/README.md).
- [analysis/](analysis/): committed machine-readable analysis of the runtime
  image (`memory_map.json`, `command_dispatch.json`, `action_table.json`,
  `rule_engine.json`), regenerable from the archived binaries.

## Backend Endpoint

```text
POST https://www.iffrc.com/ffkj/user/ble.php
Content-Type: application/x-www-form-urlencoded
```

Firmware function:

```text
fun=update
```

Observed request parameters:

| Parameter | Meaning |
|---|---|
| `fun` | Backend function. Firmware download uses `update`. |
| `id` | 24-character module ID. Required by the server. |
| `vin` | Vehicle VIN when known. |
| `isWeChat` | Mini App flag. Android replacement uses `0`. |
| `isAdmin` | Admin/factory mode flag. Normal use is `0`. |
| `appVer` | App protocol version. Mini App uses `5`. |
| `moveid` | Batch ID move/admin flag. Normal use is `0`. |
| `isapp` | Firmware target: `0` boot, `1` runtime/application. |
| `pagestart` | Starting page index requested from the server. |
| `pagelen` | Page chunk mode. `1` enables paged responses; `0` may return all pages. |

Example:

```sh
curl -X POST https://www.iffrc.com/ffkj/user/ble.php \
  --data 'fun=update&id=535C62E239E339E31475FB10&vin=5YJ3E1ET7RF889921&isWeChat=0&isAdmin=0&appVer=5&moveid=0&isapp=1&pagestart=0&pagelen=1'
```

## Response Format

Successful firmware responses contain:

| Field | Meaning |
|---|---|
| `success` | Boolean success flag. |
| `PageCount` | Total page count for the firmware image. |
| `PackSize` / `PageSize` | Page size in bytes. The observed server may use `PackSize`. |
| `BytesCount` | Total firmware byte count across all pages. |
| `CheckCode` | Per-page 16-bit additive checksum values. |
| `hex` | Firmware pages as hexadecimal strings. |

Each page starts with a 2-byte big-endian page index. The Mini App validates
that page `N` starts with bytes representing `N`, then computes the 16-bit sum
of every byte in that page and compares it against `CheckCode[N]`.

The remaining 1024 bytes of each page are executable payload. Stripping page
indices produces a 72 KiB runtime payload and a 12 KiB boot payload. The
1026-byte server stream must not be loaded directly into a disassembler as if
it were contiguous executable code.

## Download Helper

A network-only downloader is maintained in the Android project
([TSL-Cmd](https://github.com/jfryton/TSL-Cmd)) under `tools/`:

```sh
tools/download_firmware.py \
  --id 535C62E239E339E31475FB10 \
  --vin 5YJ3E1ET7RF889921 \
  --kind both \
  --chunked \
  --out ./535C62E239E339E31475FB10
```

The helper verifies:

- page sequence numbers,
- per-page additive checksums,
- total byte count,
- page size,
- final SHA-256.

It never opens BLE and never sends firmware update commands.

## Legal and Safety Notice

Use this material only where you have the right to inspect and maintain the
software and hardware. This is an independent recovery/archival project and is
not affiliated with Tesla or the original module developer. Vehicle commands can
cause physical movement or alter driving-related behavior. Test only while
parked and in a controlled setting.
