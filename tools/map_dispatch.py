#!/usr/bin/env python3
"""Map a TSL6 BLE command-dispatch comparison ladder.

The main runtime dispatcher holds the received command byte in a register
(observed: s1) and performs an ordered set of immediate comparisons that branch
to per-command handlers. This tool tracks one comparison register, finds
`c.li`/`li`/`addi rd,zero,imm` loads of command-like immediates into a scratch
register, and reports the branch that compares the command register against it,
resolving the absolute (payload) branch target.

Because this capstone build prints PC-relative displacements for branches, the
absolute target is computed as branch_addr + displacement.

Usage:
    map_dispatch.py PAYLOAD.bin START END [cmd_reg]
"""
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

CMP = {"beq", "bne", "blt", "bge", "bltu", "bgeu"}


def main():
    data = open(sys.argv[1], "rb").read()
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0)
    cmd_reg = sys.argv[4] if len(sys.argv) > 4 else "s1"
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    imm = {}  # reg -> (value, addr_loaded)
    found = []
    for ins in md.disasm(data[start:end], start):
        mn = ins.mnemonic
        ops = ins.op_str.replace(",", " ").split()
        if mn in ("c.li", "li") and len(ops) == 2:
            try:
                imm[ops[0]] = int(ops[1], 0) & 0xFFFFFFFF
            except ValueError:
                pass
            continue
        if mn == "addi" and len(ops) == 3 and ops[1] == "zero":
            imm[ops[0]] = int(ops[2], 0) & 0xFFFFFFFF
            continue
        if mn in CMP and len(ops) == 3:
            a, b, disp = ops
            other = None
            if a == cmd_reg:
                other = b
            elif b == cmd_reg:
                other = a
            if other in imm:
                val = imm[other]
                if 0x20 <= val <= 0xFF:
                    tgt = (ins.address + int(disp, 0)) & 0xFFFFFFFF
                    found.append((ins.address, mn, val, tgt))
            # consume to avoid stale reuse only if it was a hit
        # invalidate scratch regs written by non-li ops (best-effort)
        if mn not in ("c.li", "li") and len(ops) >= 1 and ops[0] in imm and mn not in CMP:
            if mn not in ("addi",):
                imm.pop(ops[0], None)
    seen = set()
    print(f"# command dispatch over {cmd_reg} in [{start:#x},{end:#x})")
    for addr, mn, val, tgt in found:
        flag = " [resident/out-of-image]" if tgt >= len(data) else ""
        key = (val, tgt)
        dup = "" if key not in seen else "  (dup)"
        seen.add(key)
        print(f"{addr:#08x}: {mn:<5} {cmd_reg}=={val:#04x} ({val:3d}) -> {tgt:#08x}{flag}{dup}")


if __name__ == "__main__":
    raise SystemExit(main())
