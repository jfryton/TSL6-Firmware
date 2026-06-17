#!/usr/bin/env python3
"""Decode the TSL6 dashboard telemetry bit-packing function.

The 0xB0 telemetry packer (payload 0xb3e0) assembles a >=33-byte packet by, for
each field:

    a0 = <signal getter>()        # jal to a per-signal accessor
    a0 &= MASK                     # andi: field width
    a5 = a0 << SHIFT               # slli: bit position within the word
    a0 = <word> & ~(MASK<<SHIFT)   # clear destination bits
    <word> |= a5                   # merge
    sw <word>, SLOT(sp)            # back to the packet word on the stack

This tool walks the function and emits, per field, the source getter address,
the field width (from the mask), the bit shift, and the destination stack slot
(which maps to a byte offset in the outgoing packet). It is a structural aid:
getter semantics still come from CLEAN_ROOM_SPEC / live correlation.

Usage:
    decode_telemetry.py PAYLOAD.bin [START] [END]
    decode_telemetry.py PAYLOAD.bin json OUT.json
"""
import json
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

START = 0xB3E0
END = 0xB76C

# Field semantics correlated from CLEAN_ROOM_SPEC section 8 (telemetry contract)
# and the Mini App decoder. Keyed by the per-signal getter address.
GETTER_LABELS = {
    0x004D14: "gear",
    0x002900: "turn signals",
    0x002D08: "autopilot state",
    0x005D42: "door state",
    0x0051EC: "state of charge",
    0x005BD0: "vehicle light/dark appearance",
    0x0076A8: "sport mode",
    0x004162: "indicator/flag bit",
    0x005D22: "indicator/flag bit",
    0x007E42: "inverter power (front/rear, signed)",
    0x004FE0: "battery heating state",
    0x0080E6: "speed units / flag",
}


def mask_width(m):
    # count contiguous low bits set
    if m == 0:
        return 0
    w = 0
    while m & 1:
        w += 1
        m >>= 1
    return w


def collect(data, start, end):
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    last_call = None
    pending_mask = None
    fields = []
    for ins in md.disasm(data[start:end], start):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn in ("jal", "c.jal"):
            try:
                last_call = (ins.address + int(ops[-1], 0)) & 0xFFFFFFFF
            except (ValueError, IndexError):
                last_call = None
            pending_mask = None
        elif mn in ("andi", "c.andi") and ops and ops[0] == "a0":
            try:
                v = int(ops[-1], 0) & 0xFFFFFFFF
            except ValueError:
                continue
            if v and (v & (v + 1)) == 0:
                pending_mask = v
        elif mn in ("slli", "c.slli") and ops and ops[0] in ("a5", "a0"):
            try:
                shift = int(ops[-1], 0)
            except ValueError:
                continue
            if last_call is not None and pending_mask is not None:
                fields.append({
                    "at": ins.address,
                    "getter": last_call,
                    "width_bits": mask_width(pending_mask),
                    "mask": pending_mask,
                    "shift": shift,
                })
                pending_mask = None
    return fields


def main():
    data = open(sys.argv[1], "rb").read()
    if len(sys.argv) > 2 and sys.argv[2] == "json":
        fields = collect(data, START, END)
        out = {
            "producer": hex(START),
            "packet_command": "0xB0",
            "min_packet_bytes": 33,
            "note": "Each field = getter() & mask, shifted into a packed word, "
                    "merged, stored to the outgoing packet. Getter semantics "
                    "correlated from CLEAN_ROOM_SPEC section 8.",
            "fields": [
                {
                    "merge_at": hex(f["at"]),
                    "getter": hex(f["getter"]),
                    "width_bits": f["width_bits"],
                    "shift": f["shift"],
                    "label": GETTER_LABELS.get(f["getter"]),
                }
                for f in fields
            ],
        }
        with open(sys.argv[3], "w") as fh:
            json.dump(out, fh, indent=2)
            fh.write("\n")
        print(f"wrote {sys.argv[3]}: {len(fields)} fields")
        return 0
    start = int(sys.argv[2], 0) if len(sys.argv) > 2 else START
    end = int(sys.argv[3], 0) if len(sys.argv) > 3 else END
    fields = collect(data, start, end)
    print(f"# telemetry fields packed in [{start:#x},{end:#x})")
    print(f"# {len(fields)} field merges detected")
    for f in fields:
        print(f"{f['at']:#08x}  getter {f['getter']:#08x}  "
              f"width={f['width_bits']:2d}  shift={f['shift']:2d}  "
              f"mask={f['mask']:#x}")


if __name__ == "__main__":
    raise SystemExit(main())
