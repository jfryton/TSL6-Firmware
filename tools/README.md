# TSL6 Firmware Analysis Tools

Self-contained, reproducible analysis tooling for the archived TSL6 images. The
only third-party dependency is [Capstone](https://www.capstone-engine.org/) with
RISC-V support (`pip install capstone`, version 5.x).

All tools operate on the **stripped payload** image (base 0), produced from the
downloaded transport image by `extract_payload.py`.

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

# 2. Regenerate machine-readable analysis artifacts
python tools/gen_analysis.py work/runtime.payload.bin analysis/
python tools/functions.py    work/runtime.payload.bin json analysis/functions.json
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
| `disasm.py` | RV32+RVC disassembly window; resolves absolute branch targets and flags out-of-image references. |
| `analyze.py` | Linker-constant (`gp`/`sp`) recovery, strings, jump-table decode, command-compare scan, word xrefs. |
| `classify_actions.py` | Decode every action stub: arguments and shared worker, grouped by reuse. |
| `map_dispatch.py` | Decode a command comparison ladder into command -> handler targets. |
| `functions.py` | Recover a function inventory and call graph (function starts, extents, callees, callers). |
| `gen_analysis.py` | Emit the committed JSON artifacts under `analysis/`. |

## Important: branch operand convention

The Capstone build used here prints **PC-relative displacements** for branch and
jump operands, not absolute addresses. Every tool here converts to an absolute
payload target as `instruction_address + displacement`. When reading raw
`disasm.py` output, the resolved target is shown after `; ->`.

Targets at or above the image size (`0x12000` for runtime) reference a resident
BLE-stack / bootloader region that is **not** contained in the downloadable
application image; they are flagged `[resident/out-of-image]`.
