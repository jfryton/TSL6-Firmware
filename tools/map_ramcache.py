#!/usr/bin/env python3
"""Map the absolute-addressed RAM signal cache of the TSL6 runtime image.

Distinct from the gp-relative state block (see map_state.py), the runtime keeps
decoded vehicle signals in high RAM (~0x2000bf00). They are reached with
PC-relative `auipc rX, HI` followed by a load/store using `LO(rX)` rather than
gp. The telemetry getters (analysis/telemetry.json) confirm ten such slots.

This tool pairs each `auipc` with the next load/store that uses the same
register, resolves the absolute target, and tabulates read/write/width per
address. The broad linear scan also crosses embedded data, so only the
telemetry-landmarked rows should be treated as confirmed without disassembly
review. Only RAM targets (0x20000000..0x20010000) are reported. The runtime
linked code base 0x8000 is included in every AUIPC calculation.

Usage:
    map_ramcache.py work/runtime.payload.bin analysis/ram_cache.json
"""
import json
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

LOAD_W = {"lw": 4, "lh": 2, "lhu": 2, "lb": 1, "lbu": 1}
STORE_W = {"sw": 4, "sh": 2, "sb": 1}
RAM_LO = 0x20000000
RAM_HI = 0x20010000
LINKED_CODE_BASE = 0x8000

# Telemetry getter -> field label (from analysis/telemetry.json) lets us name
# the cache slots each getter reads.
GETTER_LABEL = {
    0x4D14: "gear",
    0x2900: "turn signals",
    0x2D08: "autopilot state",
    0x5D42: "door state",
    0x51EC: "state of charge",
    0x5BD0: "appearance (light/dark)",
    0x76A8: "sport mode",
    0x4162: "flag bit",
    0x5D22: "flag bit",
    0x7E42: "inverter power",
    0x4FE0: "battery heating",
    0x80E6: "speed units/flag",
}


def md():
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def iter_insns(m, data):
    pos, n = 0, len(data)
    while pos < n:
        last_end = pos
        for ins in m.disasm(data[pos:], pos):
            yield ins
            last_end = ins.address + ins.size
        pos = max(last_end, pos) + 2


def parse_mem(ops):
    try:
        dest, rest = ops.split(",", 1)
    except ValueError:
        return None
    rest = rest.strip()
    if "(" not in rest or not rest.endswith(")"):
        return None
    disp_s, base = rest[:-1].split("(", 1)
    try:
        disp = int(disp_s.strip(), 0) if disp_s.strip() else 0
    except ValueError:
        return None
    return dest.strip(), base.strip(), disp


def scan(data):
    m = md()
    pending = {}   # reg -> (hi_base_addr_value)
    cache = {}     # abs_addr -> field

    def field(a):
        return cache.setdefault(a, {
            "addr": a, "addr_hex": hex(a),
            "reads": 0, "writes": 0, "widths": set(),
        })

    for ins in iter_insns(m, data):
        mn, ops = ins.mnemonic, ins.op_str
        parts = ops.replace(",", " ").split()
        if mn == "auipc" and len(parts) == 2:
            try:
                hi = (LINKED_CODE_BASE + ins.address
                      + (int(parts[1], 0) << 12)) & 0xFFFFFFFF
            except ValueError:
                continue
            pending[parts[0]] = hi
            continue
        if mn in LOAD_W or mn in STORE_W:
            parsed = parse_mem(ops)
            if not parsed:
                continue
            _dest, base, disp = parsed
            if base not in pending:
                continue
            target = (pending[base] + disp) & 0xFFFFFFFF
            # consume the pending base (single-use auipc pattern)
            del pending[base]
            if not (RAM_LO <= target < RAM_HI):
                continue
            f = field(target)
            w = LOAD_W.get(mn) or STORE_W.get(mn)
            f["widths"].add(w)
            if mn in LOAD_W:
                f["reads"] += 1
            else:
                f["writes"] += 1
        elif mn == "addi" and len(parts) == 3 and parts[1] in pending:
            # addi rD, rBaseHi, LO  -> address-taken; record but keep base
            target = (pending[parts[1]] + int(parts[2], 0)) & 0xFFFFFFFF
            if RAM_LO <= target < RAM_HI:
                field(target)  # ensure present; counted as structure base
            if parts[0] != parts[1]:
                del pending[parts[1]]

    rows = []
    for a in sorted(cache):
        f = cache[a]
        rows.append({
            "addr": a, "addr_hex": hex(a),
            "reads": f["reads"], "writes": f["writes"],
            "widths": sorted(f["widths"]),
            "mutable": f["writes"] > 0,
        })
    return rows


def scan_getters(data):
    """Resolve which absolute address each telemetry getter returns."""
    m = md()
    out = {}
    for g, label in GETTER_LABEL.items():
        pend = {}
        for ins in m.disasm(data[g:g + 0x40], g):
            parts = ins.op_str.replace(",", " ").split()
            if ins.mnemonic == "auipc" and len(parts) == 2:
                pend[parts[0]] = (LINKED_CODE_BASE + ins.address
                                  + (int(parts[1], 0) << 12)) & 0xFFFFFFFF
            elif ins.mnemonic in LOAD_W:
                pm = parse_mem(ins.op_str)
                if pm and pm[1] in pend:
                    addr = (pend[pm[1]] + pm[2]) & 0xFFFFFFFF
                    if RAM_LO <= addr < RAM_HI:
                        out.setdefault(hex(addr), []).append(
                            {"getter": hex(g), "label": label,
                             "width": LOAD_W[ins.mnemonic]})
                        break
            if ins.mnemonic in ("c.jr", "ret"):
                break
    return out


def main():
    data = open(sys.argv[1], "rb").read()
    out = sys.argv[2] if len(sys.argv) > 2 else None
    rows = scan(data)
    getters = scan_getters(data)
    assert len(data) == 0x12000
    expected_getters = {
        "0x2000be5c": ("inverter power", 2),
        "0x2000bef6": ("turn signals", 1),
        "0x2000bf00": ("autopilot state", 1),
        "0x2000bf38": ("flag bit", 1),
        "0x2000bf60": ("gear", 1),
        "0x2000bf80": ("battery heating", 1),
        "0x2000bf81": ("state of charge", 1),
        "0x2000bf84": ("appearance (light/dark)", 1),
        "0x2000bf85": ("flag bit", 1),
        "0x2000bf86": ("door state", 1),
    }
    assert {
        addr: (items[0]["label"], items[0]["width"])
        for addr, items in getters.items()
    } == expected_getters
    # annotate cache rows touched by a known getter
    for r in rows:
        if r["addr_hex"] in getters:
            r["telemetry"] = getters[r["addr_hex"]]
    doc = {
        "image": "runtime",
        "linked_code_base": hex(LINKED_CODE_BASE),
        "model": (
            "Candidate absolute-addressed RAM references recovered by a broad "
            "linear AUIPC scan. The telemetry-mapped landmarks are confirmed "
            "signal-cache slots; other rows remain heuristic because code and "
            "data are swept together."),
        "ram_window": "0x20000000-0x20010000",
        "distinct_addresses": len(rows),
        "telemetry_slots": getters,
        "addresses": rows,
    }
    text = json.dumps(doc, indent=2) + "\n"
    if out:
        with open(out, "w") as f:
            f.write(text)
        print(f"wrote {out}: {len(rows)} RAM addresses, "
              f"{len(getters)} telemetry-mapped")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
