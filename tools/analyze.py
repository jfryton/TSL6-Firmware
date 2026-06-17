#!/usr/bin/env python3
"""Structural analyzer for TSL6 stripped-payload firmware images.

Capabilities:
  - resolve linker constants (gp, sp) from the reset/startup sequence
  - resolve auipc+addi / auipc+load address pairs
  - decode the action dispatcher jump table (signed 32-bit relative entries)
  - locate and decode the BLE command dispatcher comparison ladder
  - dump ASCII strings with offsets
  - find pointer-like words into the image and into RAM/peripherals

All offsets are payload offsets (image base 0).

Usage:
    analyze.py PAYLOAD.bin gp
    analyze.py PAYLOAD.bin strings [minlen]
    analyze.py PAYLOAD.bin jtable BASE COUNT
    analyze.py PAYLOAD.bin cmds START END
    analyze.py PAYLOAD.bin xref ADDR
"""
import struct
import sys

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC

RAM_BASE = 0x20000000
PERIPH_BASE = 0x40000000


def md():
    m = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    m.detail = False
    return m


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def s32(d, o):
    return struct.unpack_from("<i", d, o)[0]


def resolve_gp(data):
    """Emulate the auipc/addi pair that loads gp, plus sp, from runtime start."""
    # follow reset jump
    m = md()
    insns = list(m.disasm(data[0:8], 0))
    target = None
    for ins in insns:
        if ins.mnemonic in ("j", "c.j", "jal", "c.jal"):
            target = int(ins.op_str.split()[-1], 0)
            break
    if target is None:
        target = 0
    regs = {}
    out = {"reset_target": target}
    code = data[target:target + 0x80]
    for ins in m.disasm(code, target):
        mn, ops = ins.mnemonic, ins.op_str.replace(",", "").split()
        if mn == "auipc" and len(ops) == 2:
            rd, imm = ops[0], int(ops[1], 0)
            regs[rd] = (ins.address + (imm << 12)) & 0xFFFFFFFF
        elif mn in ("addi", "c.addi") and len(ops) == 3 and ops[1] in regs:
            regs[ops[0]] = (regs[ops[1]] + int(ops[2], 0)) & 0xFFFFFFFF
        elif mn in ("addi",) and len(ops) == 3 and ops[0] == ops[1] and ops[0] in regs:
            regs[ops[0]] = (regs[ops[0]] + int(ops[2], 0)) & 0xFFFFFFFF
        if "gp" in regs and "sp" in regs and ins.address > target + 0x20:
            break
    out["gp"] = regs.get("gp")
    out["sp"] = regs.get("sp")
    return out


def strings(data, minlen=4):
    res = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                res.append((start, cur.decode("ascii")))
            cur = bytearray()
    if len(cur) >= minlen:
        res.append((start, cur.decode("ascii")))
    return res


def jtable(data, base, count):
    """Decode a relative jump table: target = base + s32(base + i*4)."""
    rows = []
    for i in range(count):
        off = base + i * 4
        if off + 4 > len(data):
            break
        rel = s32(data, off)
        tgt = (base + rel) & 0xFFFFFFFF
        rows.append((i, off, rel, tgt))
    return rows


def cmd_ladder(data, start, end):
    """Find immediate comparisons against command-like bytes in a window.

    Detects RVC/RV32 forms that load an immediate then branch, reporting the
    immediate and address, which reveals dispatcher command comparisons.
    """
    m = md()
    hits = []
    last_li = {}
    for ins in m.disasm(data[start:end], start):
        mn, ops = ins.mnemonic, ins.op_str.replace(",", " ").split()
        if mn in ("c.li", "li", "addi", "c.addi", "c.addiw") and len(ops) >= 2:
            try:
                val = int(ops[-1], 0)
            except ValueError:
                continue
            last_li[ops[0]] = (val & 0xFFFFFFFF, ins.address)
        if mn in ("beq", "bne", "c.beqz", "c.bnez", "bltu", "bgeu", "blt", "bge"):
            for r, (v, a) in list(last_li.items()):
                if 0x20 <= v <= 0xFF:
                    hits.append((ins.address, mn, r, v, ins.op_str))
    # also catch addi rd, rs, -imm patterns comparing command bytes
    return hits


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    data = open(sys.argv[1], "rb").read()
    cmd = sys.argv[2]
    if cmd == "gp":
        r = resolve_gp(data)
        for k, v in r.items():
            print(f"{k}: {v:#x}" if isinstance(v, int) else f"{k}: {v}")
    elif cmd == "strings":
        ml = int(sys.argv[3]) if len(sys.argv) > 3 else 4
        for off, s in strings(data, ml):
            print(f"{off:#08x}  {s}")
    elif cmd == "jtable":
        base = int(sys.argv[3], 0)
        count = int(sys.argv[4], 0)
        for i, off, rel, tgt in jtable(data, base, count):
            print(f"[{i:3d}] @{off:#08x} rel={rel:#010x} -> {tgt:#08x}")
    elif cmd == "cmds":
        start = int(sys.argv[3], 0)
        end = int(sys.argv[4], 0)
        for addr, mn, r, v, ops in cmd_ladder(data, start, end):
            print(f"{addr:#08x}: cmp {r}=={v:#04x} ({v}) via {mn} {ops}")
    elif cmd == "xref":
        target = int(sys.argv[3], 0)
        for o in range(0, len(data) - 3, 2):
            if u32(data, o) == target:
                print(f"{o:#08x}: word -> {target:#x}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
