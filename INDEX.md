# TSL6 Firmware — Master Index

A single cross-reference for everything in this repository: documents, generated
analysis artifacts, tooling, and the firmware landmarks they describe. Use this
as the entry point, then follow the links into the detailed material.

- **Module**: TSL6 BLE-to-CAN steering-wheel/media controller.
- **Platform**: WCH CH32V20x (QingKe RV32IMAC), little-endian, RVC,
  `CH32V20x_BLE_LIB_V1.3`.
- **Archived build**: module `535C62E239E339E31475FB10`, runtime `V1.0.00`,
  boot `V1.2.00`.
- **Images** (image base `0x0`, payload offsets throughout):
  - runtime `7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd`
  - boot `068c0a748ec58834258411126c610658e8008d75b88304737469a4a921f467a3`

> Safety boundary: never issue BLE update commands
> (`0x55`/`0x53`/`0x57`/`0x52`/`0x45`) without recovery hardware. See
> [README](README.md#safety-boundary) and [BOOTLOADER.md](BOOTLOADER.md).

## Related repositories

| Repo | Contents |
|---|---|
| [TSL6-Firmware](https://github.com/jfryton/TSL6-Firmware) | This repo: firmware binaries + reverse engineering. |
| [TSL-WeChat-MiniApp-Extracted](https://github.com/jfryton/TSL-WeChat-MiniApp-Extracted) | Decompiled WeChat Mini App (BLE client + action catalog). |
| [TSL-Cmd](https://github.com/jfryton/TSL-Cmd) | Android app and protocol notes. |

## Documents

| Document | What it covers |
|---|---|
| [README.md](README.md) | Overview, related repos, safety boundary, archived build, backend endpoint. |
| [FIRMWARE_INTERNALS.md](FIRMWARE_INTERNALS.md) | Component-level runtime map. Start here. |
| [BOOTLOADER.md](BOOTLOADER.md) | Boot image + flash erase/program/verify update flow. |
| [CLEAN_ROOM_SPEC.md](CLEAN_ROOM_SPEC.md) | Compatibility contract for a replacement firmware. |
| [ANALYSIS_WORKFLOW.md](ANALYSIS_WORKFLOW.md) | Reproducible extraction + disassembly process. |
| [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) | Chronological evidence trail. |
| [SESSION_NOTES.md](SESSION_NOTES.md) | Working notes. |

## Subsystem map

Each row links the prose section, the machine-readable artifact, the tool that
regenerates it, and the primary firmware entry address.

| Subsystem | Doc section | Artifact | Tool | Key address |
|---|---|---|---|---|
| Memory map / startup | [Internals §2](FIRMWARE_INTERNALS.md#2-memory-map-and-startup) | [memory_map.json](analysis/memory_map.json) | `gen_analysis.py` | reset `0xf89a`, `gp=0x1fffc000` |
| BLE command dispatch | [Internals §4](FIRMWARE_INTERNALS.md#4-main-command-dispatcher) | [command_dispatch.json](analysis/command_dispatch.json) | `gen_analysis.py` | `0xbdea` |
| Keycode primitive | [Internals §5](FIRMWARE_INTERNALS.md#5-steering-wheel--media-keycode-primitive) | [action_table.json](analysis/action_table.json) | `gen_analysis.py` | `0x33e2` |
| BLE TX path / vtable | [Internals §5a](FIRMWARE_INTERNALS.md#5a-ble-transmit-path-and-resident-stack-vtable) | [command_dispatch.json](analysis/command_dispatch.json) | `gen_analysis.py` | framer `0x110a`, vtable `0x40000000` |
| Action dispatcher / table | [Internals §6](FIRMWARE_INTERNALS.md#6-action-dispatcher-and-table) | [action_table.json](analysis/action_table.json) | `gen_analysis.py`, `classify_actions.py` | dispatch `0xd16e`, table `0x11710` |
| Shortcut rule engine | [Internals §7](FIRMWARE_INTERNALS.md#7-shortcut-rule-engine) | [rule_engine.json](analysis/rule_engine.json) | `gen_analysis.py` | `0xe310`, table `gp+0x80` |
| Rule trigger sources | [Internals §7](FIRMWARE_INTERNALS.md#trigger-event-sources) | [rule_triggers.json](analysis/rule_triggers.json) | `map_rule_triggers.py` | 33 sites |
| Firmware update relay | [Internals §8](FIRMWARE_INTERNALS.md#8-firmware-update-path) | [boot.json](analysis/boot.json) | `gen_boot_analysis.py` | relay `0xbc76` |
| Dashboard telemetry | [Internals §9](FIRMWARE_INTERNALS.md#9-dashboard-telemetry) | [telemetry.json](analysis/telemetry.json) | `decode_telemetry.py` | packer `0xb3e0` |
| HID device-name binding | [Internals §10](FIRMWARE_INTERNALS.md#10-ble-hid-device-names-and-name-binding) | [internal_commands.json](analysis/internal_commands.json) | (curated) | `0x99c0` |
| gp state block | [Internals §10a](FIRMWARE_INTERNALS.md#10a-gp-relative-state-block) | [state_block.json](analysis/state_block.json) | `map_state.py` | `gp=0x1fffc000` |
| CAN RX + signal cache | [Internals §10b](FIRMWARE_INTERNALS.md#10b-can-receive-path-and-signal-cache) | [can_map.json](analysis/can_map.json), [ram_cache.json](analysis/ram_cache.json) | `map_can.py`, `map_ramcache.py` | dispatch `0xc934` |
| Internal commands D0/D1/D2/F0 | [Internals §10c](FIRMWARE_INTERNALS.md#10c-internal-commands-d0--d1--d2--f0) | [internal_commands.json](analysis/internal_commands.json) | (curated) | `0xc060`/`0xc2da`/`0xc08c`/`0xc0ee` |
| F0 config worker / bond table | [Internals §10c](FIRMWARE_INTERNALS.md#10c-internal-commands-d0--d1--d2--f0) | [config_worker.json](analysis/config_worker.json) | (curated) | `0xa39a`, bonds `gp+0x7c` |
| Function inventory | [Internals §11](FIRMWARE_INTERNALS.md#11-recovered-function-inventory) | [functions.json](analysis/functions.json), [boot_functions.json](analysis/boot_functions.json) | `functions.py` | 419 / 84 funcs |
| Consolidated symbols | [Internals §11](FIRMWARE_INTERNALS.md#11-recovered-function-inventory) | [symbols.json](analysis/symbols.json), [boot_symbols.json](analysis/boot_symbols.json) | `gen_symbols.py` | 474 / 85 symbols |

## Bootloader (boot.bin)

| Topic | Doc section | Artifact | Key address |
|---|---|---|---|
| Identity / startup | [BOOTLOADER §1](BOOTLOADER.md#1-identity-and-startup) | [boot.json](analysis/boot.json) | reset `0x1c28`, `gp=0x20003000` |
| Update command dispatcher | [BOOTLOADER §2](BOOTLOADER.md#2-update-command-dispatcher) | [boot.json](analysis/boot.json) | `0x121c` |
| Flash write/erase/verify | [BOOTLOADER §3](BOOTLOADER.md#3-flash-write--erase--verify-flow) | [boot.json](analysis/boot.json) | program `0x110c`, ctrl `0x40021004` |
| Boot symbols | — | [boot_symbols.json](analysis/boot_symbols.json) / [.ghidra](analysis/boot_symbols.ghidra) | `gen_symbols.py --boot` |

## Command surface quick reference

Confirmed BLE command handlers (full table in
[command_dispatch.json](analysis/command_dispatch.json) and
[internal_commands.json](analysis/internal_commands.json)):

| Range | Purpose |
|---|---|
| `0xA0`–`0xAF` | Action/keycode and module-config commands. |
| `0xB0` | Dashboard telemetry stream enable/disable. |
| `0xB9`–`0xBB`, `0xC0`/`0xC1` | Status, vehicle-profile and config queries. |
| `0xD0`/`0xD1` | Notification stream enable/disable. |
| `0xD2` | Raw register/diagnostic read. |
| `0xF0` | Configuration/provisioning + bond management. |
| `0x55`/`0x53`/`0x57`/`0x52`/`0x45` | **Update transport (DANGER).** See safety boundary. |

## Reproduce everything

See [tools/README.md](tools/README.md) for setup (Capstone only). In short:

```sh
# 1. strip transport pages -> executable payloads
python tools/extract_payload.py latest-*/runtime/runtime.bin work/runtime.payload.bin
python tools/extract_payload.py latest-*/boot/boot.bin       work/boot.payload.bin

# 2. regenerate all artifacts (see analysis/README.md for the full list)
python tools/gen_analysis.py      work/runtime.payload.bin analysis/
python tools/map_state.py         work/runtime.payload.bin analysis/state_block.json
python tools/map_ramcache.py      work/runtime.payload.bin analysis/ram_cache.json
python tools/map_can.py           work/runtime.payload.bin analysis/can_map.json
python tools/map_rule_triggers.py work/runtime.payload.bin analysis/can_map.json analysis/rule_triggers.json
python tools/decode_telemetry.py  work/runtime.payload.bin json analysis/telemetry.json
python tools/functions.py         work/runtime.payload.bin json analysis/functions.json
python tools/gen_boot_analysis.py work/boot.payload.bin    analysis/boot.json
python tools/functions.py         work/boot.payload.bin    json analysis/boot_functions.json

# 3. consolidate into symbol maps (run last)
python tools/gen_symbols.py        analysis/ analysis/symbols.json      analysis/symbols.ghidra
python tools/gen_symbols.py --boot analysis/ analysis/boot_symbols.json analysis/boot_symbols.ghidra
```

All artifacts are deterministic and re-runnable from the archived binaries.
Confidence labels used throughout: **Confirmed** (from disassembly),
**Correlated** (matched to app/protocol/community data), **Inferred**, **Unknown**.
