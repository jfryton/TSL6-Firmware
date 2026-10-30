# Firmware Analysis Workflow

This repository's analyzers operate on stripped payloads derived from the
archived transport images:

```text
latest-tsl6-535C62E239E339E31475FB10/boot/boot.bin
latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin
```

## Setup and extraction

Capstone 5.x with RISC-V support is the only third-party dependency:

```sh
python3 -m venv .venv-re
.venv-re/bin/pip install capstone

B=latest-tsl6-535C62E239E339E31475FB10
.venv-re/bin/python tools/extract_payload.py "$B/runtime/runtime.bin" work/runtime.payload.bin
.venv-re/bin/python tools/extract_payload.py "$B/boot/boot.bin"       work/boot.payload.bin
```

Each transport page is a two-byte big-endian page index followed by 1024
payload bytes. `extract_payload.py` removes the two-byte prefixes and prints the
resulting hashes. Expected stripped-payload SHA-256 values:

| Image | SHA-256 |
|---|---|
| runtime | `7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd` |
| boot | `068c0a748ec58834258411126c610658e8008d75b88304737469a4a921f467a3` |

Do not mix transport offsets with payload offsets.

## Address model

Analysis JSON, prose landmarks, and symbol files use base-zero **payload
offsets** so they index the stripped files directly. Those offsets are not
linked addresses or physical flash addresses:

| Image | Payload offsets | Linked code base | Flash alias | Accepted slot |
|---|---:|---:|---:|---:|
| runtime | `0x0000..0x11fff` | `0x00008000` | `0x08008000` | `0x18000` bytes |
| boot | `0x0000..0x2fff` | `0x00001000` | `0x08001000` | `0x7000` bytes |

For example, runtime payload offset `0xf89a` has linked address `0x1789a` and
flash-alias address `0x0801789a` under the statically recovered slot mapping.
AUIPC-based absolute-address recovery must include the linked base. Both
startups resolve `gp=0x20004000` and `sp=0x20010000`.

Startup transfers to a resident BLE library at `0x00040000`; its function jump
table begins at `0x00040034`. A `lui` of `0x40` denotes this low address, not
`0x40000000`; the latter remains the CH32V peripheral region. The exact mapping
between flash aliases and these low linked/execution views is not yet known.

Both images embed `CH32V20x_BLE_LIB_V1.3`. Exact ABI names in the generated and
curated artifacts come from OpenWCH commit
`64be9554615df522899579633530fd234d685682`, file
`EVT/EXAM/BLE/LIB/wchble_rom.h`, cross-checked against each firmware call site.

## Generate artifacts

Run all structural generators before consolidating symbols:

```sh
PY=.venv-re/bin/python

$PY tools/gen_analysis.py      work/runtime.payload.bin analysis/
$PY tools/functions.py         work/runtime.payload.bin json analysis/functions.json
$PY tools/decode_telemetry.py  work/runtime.payload.bin json analysis/telemetry.json
$PY tools/map_state.py         work/runtime.payload.bin analysis/state_block.json
$PY tools/map_ramcache.py      work/runtime.payload.bin analysis/ram_cache.json
$PY tools/map_can.py           work/runtime.payload.bin analysis/can_map.json
$PY tools/map_rule_triggers.py work/runtime.payload.bin analysis/can_map.json analysis/rule_triggers.json
$PY tools/gen_boot_analysis.py work/boot.payload.bin    analysis/boot.json
$PY tools/functions.py         work/boot.payload.bin    json analysis/boot_functions.json

$PY tools/gen_symbols.py        analysis/ analysis/symbols.json      analysis/symbols.ghidra
$PY tools/gen_symbols.py --boot analysis/ analysis/boot_symbols.json analysis/boot_symbols.ghidra
```

`analysis/internal_commands.json` and `analysis/config_worker.json` are curated,
not generator outputs. Review them whenever their referenced resident ABI slots
or RAM addresses change.

## Disassembly

Use RV32 little-endian with RVC enabled. Keep the program's primary address
space at base-zero payload offsets for compatibility with the committed
artifacts. `tools/disasm.py` prints payload offsets and resolved payload branch
targets; for out-of-image transfers it also annotates the inferred linked
execution target using the image's linked base.

Known payload landmarks:

| Area | Payload offset |
|---|---:|
| Runtime reset jump | `0x0000 -> 0xf89a` |
| BLE frame builder/enqueue | `0x0d02` |
| Delayed-callback scheduler | `0x110a` |
| Main BLE command dispatcher | `0xbdea` |
| Update dispatcher | `0xbc76` |
| `0xA2` handler | `0xc53c` |
| Action dispatcher / table | `0xd16e` / `0x11710` |
| Rule engine | `0xe310` |
| Boot reset jump | `0x0000 -> 0x1c28` |
| Boot update dispatcher | `0x121c` |

## Evidence and safety standard

Every protocol or firmware claim should identify its source, exact payload
offset or source file, confidence (Confirmed, Correlated, Inferred, Unknown),
and outstanding validation. Backend action labels remain correlations until
confirmed against vehicle-side behavior.

Static analysis does not make modified firmware safe to flash. A physical
full-flash dump, option-byte/protection capture, exact remap confirmation,
tested WCH-Link recovery path, sacrificial module, and vehicle-side validation
remain prerequisites. Never exercise BLE update commands as an analysis step.
