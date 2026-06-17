#!/usr/bin/env python3
"""Map the gp-relative state block of the TSL6 runtime image.

The runtime keeps its mutable BLE/rule/telemetry state in a single block based
at the global pointer (gp=0x1fffc000). Accesses appear in two forms:

  1. Direct:        lw/lh/lb/sw/sh/sb  rD, IMM(gp)
  2. Address-taken: addi rX, gp, IMM   (then later load/store via rX, or the
                    address is passed to a helper)

This tool scans the entire image, collects every gp+IMM that is referenced,
records the access widths and whether the offset is ever written, and emits a
sorted field map. Offsets are derived purely from the disassembly, so the
result is deterministic and re-runnable.

Usage:
    map_state.py work/runtime.payload.bin analysis/state_block.json
"""
import json
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

LOAD_W = {"lw": 4, "c.lw": 4, "c.lwsp": 4,
          "lh": 2, "lhu": 2,
          "lb": 1, "lbu": 1}
STORE_W = {"sw": 4, "c.sw": 4, "c.swsp": 4,
           "sh": 2, "sb": 1}

# Annotations for offsets already confirmed elsewhere in the analysis.
KNOWN = {
    0x80: "rule engine primary shortcut table base (256 bytes, trigger/action pairs)",
    0x84: "rule engine secondary table A (36 entries x 7 bytes)",
    0x88: "rule engine secondary table B (36 entries x 7 bytes)",
    0x178: "telemetry rate-limit timestamp (0xB0 dashboard packet throttle)",
}


def md():
    m = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    return m


def parse_mem_operand(ops):
    """Return (reg_dest, base_reg, disp) for a `rD, DISP(base)` operand string."""
    # forms: "a4, 0x178(gp)"  or "a5, 0(a5)"
    try:
        dest, rest = ops.split(",", 1)
    except ValueError:
        return None
    rest = rest.strip()
    if "(" not in rest or not rest.endswith(")"):
        return None
    disp_s, base = rest[:-1].split("(", 1)
    disp_s = disp_s.strip()
    try:
        disp = int(disp_s, 0) if disp_s else 0
    except ValueError:
        return None
    return dest.strip(), base.strip(), disp


def iter_insns(m, data):
    """Linear sweep that steps over undecodable bytes.

    The image interleaves code and data tables; capstone's disasm() halts at the
    first byte it cannot decode. Restart 2 bytes later (RVC alignment) until the
    end so code regions after data tables are still covered.
    """
    pos = 0
    n = len(data)
    while pos < n:
        last_end = pos
        for ins in m.disasm(data[pos:], pos):
            yield ins
            last_end = ins.address + ins.size
        # disasm stalled (data byte) at last_end; resync on next 2-byte boundary
        pos = max(last_end, pos) + 2


def scan(data):
    m = md()
    fields = {}   # offset -> dict

    def field(off):
        return fields.setdefault(off, {
            "offset": off,
            "offset_hex": hex(off),
            "reads": 0,
            "writes": 0,
            "widths": set(),
            "addr_taken": 0,
            "first_seen": None,
        })

    seen = set()
    for ins in iter_insns(m, data):
        if ins.address in seen:
            continue
        seen.add(ins.address)
        mn = ins.mnemonic
        ops = ins.op_str
        # Form 2: addi rX, gp, IMM  (address-taken)
        if mn in ("addi", "c.addi"):
            parts = ops.replace(",", " ").split()
            if len(parts) == 3 and parts[1] == "gp":
                try:
                    off = int(parts[2], 0)
                except ValueError:
                    off = None
                if off is not None and off >= 0:
                    f = field(off)
                    f["addr_taken"] += 1
                    if f["first_seen"] is None:
                        f["first_seen"] = hex(ins.address)
            continue
        # Form 1: direct load/store with (gp) base
        if mn in LOAD_W or mn in STORE_W:
            parsed = parse_mem_operand(ops)
            if not parsed:
                continue
            _dest, base, disp = parsed
            if base != "gp" or disp < 0:
                continue
            f = field(disp)
            width = LOAD_W.get(mn) or STORE_W.get(mn)
            f["widths"].add(width)
            if mn in LOAD_W:
                f["reads"] += 1
            else:
                f["writes"] += 1
            if f["first_seen"] is None:
                f["first_seen"] = hex(ins.address)

    rows = []
    for off in sorted(fields):
        f = fields[off]
        rows.append({
            "offset": off,
            "offset_hex": f["offset_hex"],
            "direct_reads": f["reads"],
            "direct_writes": f["writes"],
            "access_widths": sorted(f["widths"]),
            "address_taken": f["addr_taken"],
            "first_ref": f["first_seen"],
            "mutable": f["writes"] > 0,
            "note": KNOWN.get(off),
        })
    return rows


def main():
    data = open(sys.argv[1], "rb").read()
    out = sys.argv[2] if len(sys.argv) > 2 else None
    rows = scan(data)
    direct = [r for r in rows if r["direct_reads"] or r["direct_writes"]]
    addr_only = [r for r in rows if not (r["direct_reads"] or r["direct_writes"])]
    doc = {
        "image": "runtime",
        "global_pointer_gp": "0x1fffc000",
        "model": (
            "Single gp-based state block. 'direct' offsets are touched by "
            "lw/lh/lb/sw/sh/sb with (gp) base; 'address_taken' offsets are the "
            "base of sub-structures/arrays passed by pointer (e.g. the rule "
            "tables). Widths and write counts indicate scalar fields vs. "
            "structure bases."),
        "distinct_offsets": len(rows),
        "directly_accessed": len(direct),
        "address_taken_only": len(addr_only),
        "fields": rows,
    }
    text = json.dumps(doc, indent=2) + "\n"
    if out:
        with open(out, "w") as f:
            f.write(text)
        print(f"wrote {out}: {len(rows)} offsets "
              f"({len(direct)} direct, {len(addr_only)} address-taken)")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
