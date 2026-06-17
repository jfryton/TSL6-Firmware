# Firmware Analysis Workflow

## Inputs

Use the archived 1026-byte-page transport images:

```text
latest-tsl6-535C62E239E339E31475FB10/boot/boot.bin
latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin
```

## Generate Maps

The mapper is maintained in the Android repository
([TSL-Cmd](https://github.com/jfryton/TSL-Cmd), `tools/`):

```sh
tools/.venv-re/bin/python \
  tools/map_firmware.py \
  latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.bin \
  --out latest-tsl6-535C62E239E339E31475FB10/runtime/runtime.map.json
```

Repeat with `boot/boot.bin` and `boot/boot.map.json`.

The map records:

- Transport-page validity and checksums.
- Hashes for both transport and stripped payload forms.
- Candidate vectors and pointers.
- Strings.
- Protocol-command immediate hits.
- Candidate relative jump tables.
- Known action-table hypotheses.
- Disassembly windows.

## Extract a Raw Payload

The executable payload is obtained by removing the first two bytes from every
1026-byte transport page:

```python
payload = b"".join(
    transport[offset + 2 : offset + 1026]
    for offset in range(0, len(transport), 1026)
)
```

Expected hashes:

| Image | SHA-256 stripped payload |
|---|---|
| runtime | `7adcb4622f017714a4896060522ce0076e8f0ff94511845d1b9d15b49dd677fd` |
| boot | `068c0a748ec58834258411126c610658e8008d75b88304737469a4a921f467a3` |

## Disassembly

Use RV32 little-endian with RVC enabled and image base zero.

Known payload landmarks:

| Area | Offset |
|---|---:|
| Runtime reset jump | `0x0000` -> `0xF89A` |
| Main BLE command dispatcher | near `0xBDEA` |
| Update dispatcher | near `0xBC76` |
| `0xA2` handler | near `0xC53C` |
| Action dispatcher | `0xD16E` |
| Action jump-table setup | `0xD1E0` |
| Action table | `0x11710` |
| Rule engine | `0xE310` |
| Boot reset jump | `0x0000` -> `0x1C28` |

Do not mix transport offsets with payload offsets.

## Evidence Standard

Every protocol or firmware claim should identify:

- Source: Mini App, backend catalog, runtime, bootloader, or live capture.
- Exact offset or source file.
- Confidence: confirmed, correlated, inferred, or unknown.
- Validation still required.

Vehicle-side action meanings are not considered confirmed solely because the
backend catalog supplies a label. Confirm with passive observation or trace
correlation before using them in safety-sensitive firmware.
