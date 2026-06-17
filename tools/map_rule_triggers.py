#!/usr/bin/env python3
"""Map the rule-engine trigger event sources of the TSL6 runtime image.

The shortcut rule engine at 0xe310 takes a single argument a0 = an 8-bit event
code, scans the primary table at gp+0x80 for a matching trigger byte, and fires
the paired action through the action dispatcher 0xd16e. Triggers are raised from
~33 call sites, predominantly inside the per-CAN-ID signal decoders: when a
watched vehicle signal changes, the decoder calls the rule engine with the
event code for that transition.

This tool finds every call to 0xe310, recovers the immediate event code in a0
when it is a constant (`c.li a0,N` / `addi a0,zero,N`), marks the rest as
register-computed (the trigger is a decoded enum value, e.g. a gear/AP state),
and attributes each site to the nearest preceding CAN decoder from can_map.json.

Usage:
    map_rule_triggers.py work/runtime.payload.bin analysis/can_map.json \
        analysis/rule_triggers.json
"""
import json
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

RULE_ENGINE = 0xE310
BACK_WINDOW = 0x28  # bytes to scan back for the a0 set


def md():
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def iter_insns(m, data):
    pos, n = 0, len(data)
    while pos < n:
        last = pos
        for ins in m.disasm(data[pos:], pos):
            yield ins
            last = ins.address + ins.size
        pos = max(last, pos) + 2


def find_callers(data):
    m = md()
    sites = []
    for ins in iter_insns(m, data):
        if ins.mnemonic in ("jal", "c.jal", "j", "c.j"):
            p = ins.op_str.replace(",", " ").split()
            try:
                tgt = (ins.address + int(p[-1], 0)) & 0xFFFFFFFF
            except (ValueError, IndexError):
                continue
            if tgt == RULE_ENGINE:
                sites.append((ins.address, ins.mnemonic))
    # de-dup (resync sweep can revisit)
    return sorted(set(sites))


def a0_const_before(data, addr):
    m = md()
    start = max(0, addr - BACK_WINDOW)
    last = None
    for ins in m.disasm(data[start:addr + 2], start):
        if ins.address >= addr:
            break
        p = ins.op_str.replace(",", " ").split()
        if ins.mnemonic in ("c.li", "li") and len(p) == 2 and p[0] == "a0":
            last = int(p[1], 0) & 0xFFFFFFFF
        elif ins.mnemonic == "addi" and len(p) == 3 and p[0] == "a0" \
                and p[1] == "zero":
            last = int(p[2], 0) & 0xFFFFFFFF
        elif ins.mnemonic in ("mv", "c.mv") and len(p) == 2 and p[0] == "a0":
            last = None  # a0 comes from a register (computed trigger)
    return last


def main():
    data = open(sys.argv[1], "rb").read()
    can = json.load(open(sys.argv[2]))
    out = sys.argv[3] if len(sys.argv) > 3 else None

    decoders = sorted(
        (int(r["decoder"], 16), r["can_id_hex"], r.get("label"))
        for r in can["ids"] if r["decoder"])

    def owner(addr):
        best = None
        for d, cid, lab in decoders:
            if d <= addr:
                best = (d, cid, lab)
            else:
                break
        if best and addr - best[0] < 0x400:
            return best
        return None

    sites = find_callers(data)
    rows = []
    for addr, mn in sites:
        tv = a0_const_before(data, addr)
        own = owner(addr)
        rows.append({
            "call_site": hex(addr),
            "call_kind": mn,
            "trigger_code": hex(tv) if tv is not None else None,
            "trigger_computed": tv is None,
            "in_can_decoder": hex(own[0]) if own else None,
            "can_id": own[1] if own else None,
            "can_label": own[2] if own else None,
        })

    const = [r for r in rows if r["trigger_code"]]
    doc = {
        "image": "runtime",
        "rule_engine": hex(RULE_ENGINE),
        "trigger_arg": "a0 (8-bit event code)",
        "action_dispatch": "0xd16e",
        "primary_table": "gp+0x80 (trigger,action pairs)",
        "model": (
            "CAN/signal decoders and input handlers raise an 8-bit event code "
            "into the rule engine; the engine maps event->action via the user "
            "shortcut table. Constant trigger codes are fixed transitions; "
            "'computed' triggers derive the code from a decoded signal enum "
            "(e.g. gear/AP state) at runtime."),
        "call_site_count": len(rows),
        "constant_trigger_count": len(const),
        "distinct_constant_codes": sorted(
            {r["trigger_code"] for r in const},
            key=lambda x: int(x, 16)),
        "call_sites": rows,
    }
    text = json.dumps(doc, indent=2) + "\n"
    if out:
        with open(out, "w") as f:
            f.write(text)
        print(f"wrote {out}: {len(rows)} rule-engine call sites, "
              f"{len(const)} with constant trigger codes")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    raise SystemExit(main())
