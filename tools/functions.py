#!/usr/bin/env python3
"""Function discovery and call-graph extraction for TSL6 payload images.

Strategy (no symbols available):
  1. Seed function starts from:
       - the reset/startup entry,
       - every `jal`/`c.jal` target (direct call destinations),
       - prologue patterns (`c.addi sp,-imm`, `addi sp,sp,-imm`).
  2. For each seed, linearly decode until a clear function terminator
     (`c.jr ra` / `ret`, or an unconditional tail `j` that leaves the
     function body) while tracking the max address reached, to estimate extent.
  3. Record direct callees (`jal`/`c.jal`) per function to build a call graph.

Because the Capstone build prints PC-relative displacements for branches/jumps,
absolute targets are computed as addr + displacement.

This is a heuristic recovery aid, not a perfect CFG. It deliberately favors
direct-call evidence (high precision) over exhaustive sweep.

Usage:
    functions.py PAYLOAD.bin inventory          # list discovered functions
    functions.py PAYLOAD.bin callers 0x33e2     # who calls this address
    functions.py PAYLOAD.bin callees 0xbdea     # direct callees of a function
    functions.py PAYLOAD.bin json OUT.json      # dump inventory + call graph
"""
import json
import struct
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

CALL = {"jal", "c.jal"}
UNCOND = {"j", "c.j"}
RET = {"ret", "c.jr"}  # c.jr ra acts as return


def md():
    return Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


def disp_target(ins):
    ops = ins.op_str.replace(",", " ").split()
    try:
        return (ins.address + int(ops[-1], 0)) & 0xFFFFFFFF
    except (ValueError, IndexError):
        return None


def all_direct_calls(data):
    """One linear sweep with gap-restart; collect every direct call target."""
    m = md()
    n = len(data)
    pos = 0
    calls = []  # (caller_addr, target)
    call_targets = set()
    prologues = set()
    while pos < n - 1:
        progressed = False
        for ins in m.disasm(data[pos:], pos):
            progressed = True
            mn = ins.mnemonic
            if mn in CALL:
                t = disp_target(ins)
                if t is not None and t < n:
                    calls.append((ins.address, t))
                    call_targets.add(t)
            elif mn == "c.addi" and "sp" in ins.op_str and "-" in ins.op_str:
                prologues.add(ins.address)
            elif mn == "addi" and ins.op_str.startswith("sp, sp, -"):
                prologues.add(ins.address)
            elif mn == "c.addi16sp" and "-" in ins.op_str:
                prologues.add(ins.address)
            pos = ins.address + ins.size
        if not progressed:
            pos += 2
    return calls, call_targets, prologues


def function_extent(data, start, starts):
    """Estimate a function's end by linear decode until ret or it runs into the
    next known function start. Returns (end, callees)."""
    m = md()
    n = len(data)
    callees = []
    addr = start
    last = start
    while addr < n - 1:
        chunk = data[addr:addr + 64]
        decoded = False
        for ins in m.disasm(chunk, addr):
            decoded = True
            mn = ins.mnemonic
            last = ins.address + ins.size
            if mn in CALL:
                t = disp_target(ins)
                if t is not None:
                    callees.append(t)
            if mn in RET or mn == "mret":
                # c.jr with ra is a return; c.jr with other reg may be a switch
                if mn == "ret" or ins.op_str.strip() in ("ra",):
                    return last, callees
            if mn in UNCOND:
                # tail call / end of straightline body
                return last, callees
            nxt = ins.address + ins.size
            if nxt in starts and nxt != start:
                return nxt, callees
            addr = nxt
            break
        if not decoded:
            addr += 2
    return min(last, n), callees


def build(data):
    calls, call_targets, prologues = all_direct_calls(data)
    starts = set(call_targets)
    # include reset entry
    m = md()
    for ins in m.disasm(data[0:8], 0):
        if ins.mnemonic in UNCOND:
            t = disp_target(ins)
            if t is not None:
                starts.add(t)
        break
    funcs = {}
    callgraph = defaultdict(list)
    for s in sorted(starts):
        end, callees = function_extent(data, s, starts)
        funcs[s] = {"start": s, "end": end, "size": end - s,
                    "callees": sorted(set(c for c in callees if c in starts))}
    callers = defaultdict(set)
    for caller, tgt in calls:
        # attribute to enclosing function (largest start <= caller)
        owner = None
        for s in sorted(starts):
            if s <= caller:
                owner = s
            else:
                break
        if owner is not None:
            callers[tgt].add(owner)
            callgraph[owner].append(tgt)
    return funcs, callers, callgraph, calls


def main():
    data = open(sys.argv[1], "rb").read()
    cmd = sys.argv[2]
    funcs, callers, callgraph, calls = build(data)
    if cmd == "inventory":
        print(f"# {len(funcs)} candidate functions")
        for s in sorted(funcs):
            f = funcs[s]
            nc = len(callers.get(s, ()))
            print(f"{s:#08x}  size={f['size']:5d}  callers={nc:3d}  "
                  f"callees={len(f['callees'])}")
    elif cmd == "callers":
        tgt = int(sys.argv[3], 0)
        cs = sorted(callers.get(tgt, ()))
        print(f"# {len(cs)} callers of {tgt:#x}")
        for c in cs:
            print(f"  {c:#08x}")
    elif cmd == "callees":
        s = int(sys.argv[3], 0)
        print(f"# direct callees of {s:#x}")
        for c in sorted(set(callgraph.get(s, ()))):
            print(f"  {c:#08x}  (callers={len(callers.get(c, ()))})")
    elif cmd == "json":
        out = {
            "function_count": len(funcs),
            "functions": [funcs[s] for s in sorted(funcs)],
            "callers": {hex(k): sorted(f"{x:#x}" for x in v)
                        for k, v in sorted(callers.items())},
        }
        with open(sys.argv[3], "w") as fh:
            json.dump(out, fh, indent=2)
            fh.write("\n")
        print(f"wrote {sys.argv[3]}: {len(funcs)} functions")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
