#!/usr/bin/env python3
"""Classify TSL6 runtime action-handler stubs.

Each entry in the action jump table at payload 0x11710 points to a short stub.
The stubs follow a small number of shapes:

  - restore dispatcher frame (lwsp ra/s0/s1/s2), load 1-3 small immediates into
    argument registers, then tail-call a shared worker via `j`.
  - a bare default stub shared by unused action IDs.

This tool decodes every stub, extracts the immediates placed in a0..a3 and the
tail-call target, and groups handlers by (worker_target, args). That grouping
exposes which actions are parameterized calls into the same primitive.

Usage:
    classify_actions.py PAYLOAD.bin BASE COUNT
"""
import struct
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC


def md():
    m = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    return m


def s32(d, o):
    return struct.unpack_from("<i", d, o)[0]


def decode_stub(data, addr, limit=0x40):
    """Walk a stub until its terminating jump; record arg immediates + target."""
    m = md()
    args = {}
    target = None
    kind = None
    for ins in m.disasm(data[addr:addr + limit], addr):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn in ("c.li", "li") and len(ops) == 2:
            try:
                args[ops[0]] = int(ops[1], 0) & 0xFFFFFFFF
            except ValueError:
                pass
        elif mn == "addi" and len(ops) == 3 and ops[1] == "zero":
            args[ops[0]] = int(ops[2], 0) & 0xFFFFFFFF
        elif mn in ("c.mv",) and len(ops) == 2:
            args[ops[0]] = f"={ops[1]}"
        elif mn in ("j", "c.j"):
            target = (ins.address + int(ops[-1], 0)) & 0xFFFFFFFF
            kind = "tail"
            break
        elif mn in ("jal", "c.jal"):
            target = (ins.address + int(ops[-1], 0)) & 0xFFFFFFFF
            kind = "call"
            break
        elif mn in ("c.jr", "jr", "ret", "c.jalr", "jalr"):
            kind = "indirect/ret"
            break
    keep = {k: v for k, v in args.items() if k in ("a0", "a1", "a2", "a3")}
    return kind, target, keep


def main():
    data = open(sys.argv[1], "rb").read()
    base = int(sys.argv[2], 0)
    count = int(sys.argv[3], 0)
    groups = defaultdict(list)
    rows = []
    for i in range(count):
        off = base + i * 4
        tgt = (base + s32(data, off)) & 0xFFFFFFFF
        kind, worker, args = decode_stub(data, tgt)
        action_id = i + 1  # dispatcher does (action_id - 1)
        key = (worker, tuple(sorted(args.items())))
        groups[key].append(action_id)
        rows.append((action_id, tgt, kind, worker, args))
    for action_id, tgt, kind, worker, args in rows:
        ws = f"{worker:#08x}" if isinstance(worker, int) else str(worker)
        print(f"action {action_id:3d}  stub {tgt:#08x}  {kind:>6}->{ws}  args={args}")
    print("\n=== grouped by (worker,args) ===")
    for (worker, args), ids in sorted(
        groups.items(), key=lambda kv: -len(kv[1])
    ):
        ws = f"{worker:#08x}" if isinstance(worker, int) else str(worker)
        rng = ",".join(str(x) for x in ids)
        print(f"worker {ws} args={dict(args)}  x{len(ids)}: {rng}")


if __name__ == "__main__":
    raise SystemExit(main())
