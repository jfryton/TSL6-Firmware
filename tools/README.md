# TSL6 Firmware Analysis Tools

Self-contained, reproducible analysis tooling for the archived TSL6 images. The
only third-party dependency is [Capstone](https://www.capstone-engine.org/) with
RISC-V support (`pip install capstone`, version 5.x).

All tools operate on the **stripped payload** image. They report base-zero
payload offsets so addresses index the file directly. Runtime is linked at
`0x8000` and boot at `0x1000`; tools resolving AUIPC absolute addresses include
that linked base.

## Setup

```sh
python3 -m venv .venv-re
.venv-re/bin/pip install capstone
```

## Workflow

```sh
B=latest-tsl6-535C62E239E339E31475FB10

# 1. Strip transport pages -> executable payload
python tools/extract_payload.py $B/runtime/runtime.bin work/runtime.payload.bin
python tools/extract_payload.py $B/boot/boot.bin       work/boot.payload.bin

# 2. Regenerate structural artifacts
python tools/gen_analysis.py work/runtime.payload.bin analysis/
python tools/functions.py work/runtime.payload.bin json analysis/functions.json
python tools/decode_telemetry.py work/runtime.payload.bin json analysis/telemetry.json
python tools/map_state.py work/runtime.payload.bin analysis/state_block.json
python tools/map_ramcache.py work/runtime.payload.bin analysis/ram_cache.json
python tools/map_can.py work/runtime.payload.bin analysis/can_map.json
python tools/map_rule_triggers.py work/runtime.payload.bin analysis/can_map.json analysis/rule_triggers.json
python tools/gen_boot_analysis.py work/boot.payload.bin analysis/boot.json
python tools/functions.py work/boot.payload.bin json analysis/boot_functions.json

# 3. Consolidate symbols after all structural artifacts
python tools/gen_symbols.py analysis/ analysis/symbols.json analysis/symbols.ghidra
python tools/gen_symbols.py --boot analysis/ analysis/boot_symbols.json analysis/boot_symbols.ghidra
```

Expected stripped-payload SHA-256:

| Image | SHA-256 |
|---|---|
| runtime | `7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd` |
| boot | `068c0a748ec58834258411126c610658e8008d75b88304737469a4a921f467a3` |

## Tools

| Tool | Purpose |
|---|---|
| `extract_payload.py` | Strip 1026-byte transport pages into a contiguous payload. |
| `disasm.py` | RV32+RVC disassembly window; resolves payload branch targets and annotates linked targets for out-of-image references. |
| `analyze.py` | Linker-constant (`gp`/`sp`) recovery, strings, jump-table decode, command-compare scan, word xrefs. |
| `classify_actions.py` | Decode every action stub: arguments and shared worker, grouped by reuse. |
| `map_dispatch.py` | Decode a command comparison ladder into command -> handler targets. |
| `functions.py` | Recover a function inventory and call graph (function starts, extents, callees, callers). |
| `decode_telemetry.py` | Decode the dashboard telemetry packer into a per-field getter/width/shift map. |
| `map_state.py` | Map the gp-relative state block: every `gp+IMM` field with access widths, read/write counts, and structure-base detection. |
| `map_ramcache.py` | Heuristically map absolute RAM references in `0x20000000`-`0x20010000` and tie landmark-checked telemetry getters to signal-cache slots. |
| `map_can.py` | Decode the CAN-ID dispatch table into CAN ID -> decoder mappings (inline vs. raw-frame-stored). |
| `map_rule_triggers.py` | Find all rule-engine call sites and recover each trigger event code, attributed to its source CAN decoder. |
| `gen_analysis.py` | Emit the committed runtime JSON artifacts under `analysis/`. |
| `gen_boot_analysis.py` | Emit the committed bootloader artifact `analysis/boot.json`. |
| `gen_symbols.py` | Consolidate all artifacts into one symbol map + Ghidra import file (`--boot` for the boot image). |

## Address and branch conventions

Keep these three address spaces distinct:

| Image | Payload offsets | Linked base | Flash alias |
|---|---:|---:|---:|
| runtime | base `0x0` | `0x00008000` | `0x08008000` |
| boot | base `0x0` | `0x00001000` | `0x08001000` |

The resident BLE library begins at `0x00040000` and its function jump table at
`0x00040034`; neither is the CH32V peripheral region at `0x40000000`. Both
startups recover `gp=0x20004000` and `sp=0x20010000`. Exact jump-table names
are sourced from OpenWCH commit
`64be9554615df522899579633530fd234d685682`, header
`EVT/EXAM/BLE/LIB/wchble_rom.h`, matching the embedded library version string.

The Capstone build used here prints **PC-relative displacements** for branch and
jump operands, not absolute addresses. Every tool here converts to an absolute
payload target as `instruction_address + displacement`. `disasm.py` keeps that
payload target primary and, for an out-of-image transfer, also prints the
inferred linked execution target using the image's linked base.

Targets at or above the image size (`0x12000` for runtime) reference a resident
region that is **not** contained in the downloadable image. The exact flash-
alias remap into this linked execution view remains unconfirmed.
