#!/usr/bin/env python3
"""Map the CAN-ID dispatch table of the TSL6 runtime image.

The runtime receives vehicle CAN frames and decodes a fixed set of message IDs
into the absolute RAM signal cache (see map_ramcache.py). The dispatcher at
0xC934 reads the 11-bit CAN ID from the frame header (`lhu a5, 0(s0)`), then
walks a balanced comparison tree of `addi a4,zero,ID ; beq/bne a5,a4` tests.
Each matched arm falls through (or branches) to a short trampoline that reloads
the frame pointer (`mv a0,s0`) and tail-jumps to the per-ID decoder.

This tool:
  1. parses the comparison tree to recover {CAN ID -> trampoline},
  2. follows the trampoline's terminal j/jal to the real decoder entry,
  3. emits a deterministic CAN ID -> decoder map.

CAN IDs are reported in hex (Tesla Model 3/Y chassis/powertrain bus IDs).

Usage:
    map_can.py work/runtime.payload.bin analysis/can_map.json
"""
import json
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

DISPATCH_START = 0xC934
DISPATCH_END = 0xCB00
# Trampoline scan window for resolving the terminal tail-call.
TRAMPOLINE_LIMIT = 0x20

# Correlated CAN ID labels. Tesla Model 3/Y IDs are widely documented in the
# open Model3CAN/DBC community work; these are correlated, not confirmed against
# this specific vehicle harness.
CAN_ID_LABEL = {
    0x82: "correlated: steering/control input",
    0x102: "correlated: body/door status (VCLEFT/RIGHT)",
    0x103: "correlated: body status",
    0x118: "correlated: DriveSystemStatus (gear/AP)",
    0x129: "correlated: SteeringAngle",
    0x132: "correlated: HV battery (volt/current/SoC)",
    0x1F9: "correlated: drive/torque",
    0x20C: "correlated: VCRIGHT door/latch",
    0x229: "correlated: gear lever / stalk",
    0x238: "correlated: drive inverter",
    0x249: "correlated: chassis",
    0x257: "correlated: DIspeed (vehicle speed)",
    0x25A: "correlated: body",
    0x25D: "correlated: body",
    0x266: "correlated: rear inverter power",
    0x273: "correlated: UI/driver assist",
    0x293: "correlated: UI/autopilot status",
    0x2B4: "correlated: chassis",
    0x2B6: "correlated: chassis",
    0x2E1: "correlated: VCFRONT status",
    0x2E5: "correlated: front inverter power",
    0x2F3: "correlated: UI trip/range",
    0x31F: "correlated: chassis",
    0x321: "correlated: VCFRONT sensors (temps)",
    0x332: "correlated: battery brick voltages",
    0x333: "correlated: UI charge",
    0x339: "correlated: UI range",
    0x352: "correlated: BMS energy status (SoC)",
    0x370: "correlated: BMS",
    0x39D: "correlated: autopilot/steering",
    0x3DF: "correlated: UI/odometer",
}


def md():
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def parse_tree(data):
    m = md()
    ins = list(m.disasm(data[DISPATCH_START:DISPATCH_END], DISPATCH_START))
    arms = {}
    imm = None
    for i, x in enumerate(ins):
        p = x.op_str.replace(",", " ").split()
        if x.mnemonic in ("addi",) and len(p) == 3 and p[1] == "zero":
            imm = int(p[2], 0)
        elif x.mnemonic == "c.li" and len(p) == 2:
            imm = int(p[1], 0)
        elif x.mnemonic == "beq" and "a5" in p and "a4" in p:
            tgt = (x.address + int(p[-1], 0)) & 0xFFFFFFFF
            if imm and imm > 0x40:
                arms.setdefault(imm, ("beq", tgt))
        elif x.mnemonic == "bne" and "a5" in p and "a4" in p:
            nt = ins[i + 1].address if i + 1 < len(ins) else None
            if imm and imm > 0x40 and nt is not None:
                arms.setdefault(imm, ("bne-fallthrough", nt))
    return arms


# Shared raw-frame store routine: copies the 12-byte CAN frame into a RAM
# frame-buffer slot (RAM 0x200043... base) for later decoding, rather than
# extracting a scalar signal immediately.
RAW_FRAME_STORE = 0x28E


def resolve_decoder(data, tramp):
    """Follow a trampoline's terminal j/jal to the decoder entry.

    Some trampolines (e.g. 0xcc54) themselves tail into the shared raw-frame
    store at 0x28e; collapse one extra hop so the reported decoder is the
    routine that actually consumes the frame.
    """
    m = md()
    hops = 0
    while hops < 2:
        nxt = None
        for x in m.disasm(data[tramp:tramp + TRAMPOLINE_LIMIT], tramp):
            if x.mnemonic in ("j", "c.j", "jal", "c.jal"):
                p = x.op_str.replace(",", " ").split()
                try:
                    nxt = (x.address + int(p[-1], 0)) & 0xFFFFFFFF
                    via = x.mnemonic
                except ValueError:
                    return None, None
                break
            if x.mnemonic in ("c.jr", "jr", "ret"):
                return None, x.mnemonic
        if nxt is None:
            return None, None
        # collapse a pure trampoline (cc54-style) into its raw-frame target
        if nxt != RAW_FRAME_STORE and _is_trampoline(data, nxt):
            tramp = nxt
            hops += 1
            continue
        return nxt, via
    return tramp, "trampoline-chain"


def _is_trampoline(data, addr):
    """True if addr is a short stub whose body is just epilogue + tail jump."""
    m = md()
    body = list(m.disasm(data[addr:addr + TRAMPOLINE_LIMIT], addr))
    if not body:
        return False
    real = [x for x in body if x.mnemonic not in (
        "c.lwsp", "c.swsp", "c.li", "c.addi", "c.mv", "addi")]
    return bool(real) and real[0].mnemonic in ("j", "c.j")


def main():
    data = open(sys.argv[1], "rb").read()
    out = sys.argv[2] if len(sys.argv) > 2 else None
    arms = parse_tree(data)
    rows = []
    for cid in sorted(arms):
        how, tramp = arms[cid]
        dec, via = resolve_decoder(data, tramp)
        is_raw = isinstance(dec, int) and dec == RAW_FRAME_STORE
        rows.append({
            "can_id": cid,
            "can_id_hex": hex(cid),
            "match": how,
            "trampoline": hex(tramp),
            "decoder": hex(dec) if isinstance(dec, int) else None,
            "decoder_via": via,
            "stored_raw": is_raw,
            "label": CAN_ID_LABEL.get(cid),
        })
    doc = {
        "image": "runtime",
        "dispatcher": hex(DISPATCH_START),
        "frame_pointer_register": "s0 (a0 on entry)",
        "can_id_load": "lhu a5, 0(s0)  (11-bit ID at frame offset 0)",
        "model": (
            "RX CAN frame -> binary-search comparison tree on the 11-bit ID -> "
            "per-ID trampoline (reload frame ptr, tail-call) -> signal decoder "
            "that writes the absolute RAM signal cache sampled by telemetry."),
        "raw_frame_store": {
            "addr": hex(RAW_FRAME_STORE),
            "note": "IDs flagged stored_raw copy the 12-byte frame into a RAM "
                    "frame-buffer slot (indexed, stride 12) for deferred "
                    "decoding instead of extracting a scalar inline.",
        },
        "decoded_id_count": len(rows),
        "ids": rows,
    }
    text = json.dumps(doc, indent=2) + "\n"
    if out:
        with open(out, "w") as f:
            f.write(text)
        print(f"wrote {out}: {len(rows)} decoded CAN IDs")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
