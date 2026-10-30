#!/usr/bin/env python3
"""RISC-V (RV32 + compressed) disassembly window over a stripped payload image.

The TSL6 firmware is WCH CH32V20x (QingKe RV32IMAC) code, little-endian, with
compressed (RVC) instructions. Primary addresses are payload offsets. For a
branch outside a known image, the linked execution target is also shown.

Usage:
    disasm.py PAYLOAD.bin --start 0xBDEA --count 160
    disasm.py PAYLOAD.bin --start 0xD16E --end 0xD260
"""
import argparse

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC


def make_md() -> Cs:
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)
    md.detail = False
    return md


BRANCH = {"beq", "bne", "blt", "bge", "bltu", "bgeu",
          "c.beqz", "c.bnez", "j", "c.j", "jal", "c.jal"}
LINKED_BASE_BY_SIZE = {0x12000: 0x8000, 0x3000: 0x1000}


def _abs_target(addr: int, mn: str, ops: str):
    """This capstone build prints PC-relative displacements for branches/jumps.

    Return absolute target = addr + displacement for those forms.
    """
    if mn not in BRANCH:
        return None
    try:
        disp = int(ops.replace(",", " ").split()[-1], 0)
    except (ValueError, IndexError):
        return None
    return (addr + disp) & 0xFFFFFFFF


def disasm(data: bytes, start: int, end: int):
    md = make_md()
    code = data[start:end]
    rows = []
    for insn in md.disasm(code, start):
        raw = insn.bytes.hex()
        tgt = _abs_target(insn.address, insn.mnemonic, insn.op_str)
        rows.append((insn.address, raw, insn.mnemonic, insn.op_str, tgt))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("payload")
    ap.add_argument("--start", required=True)
    ap.add_argument("--count", type=int, default=80, help="instruction count cap")
    ap.add_argument("--end", default=None, help="stop offset (overrides count length)")
    args = ap.parse_args()
    data = open(args.payload, "rb").read()
    linked_base = LINKED_BASE_BY_SIZE.get(len(data))
    start = int(args.start, 0)
    if args.end is not None:
        end = int(args.end, 0)
    else:
        end = min(len(data), start + args.count * 4)
    n = 0
    for addr, raw, mn, ops, tgt in disasm(data, start, end):
        ann = ""
        if tgt is not None:
            ann = f"   ; -> {tgt:#08x}"
            if tgt >= len(data):
                ann += " [resident/out-of-image"
                if linked_base is not None:
                    linked_target = (linked_base + tgt) & 0xFFFFFFFF
                    ann += f"; linked -> {linked_target:#08x}"
                ann += "]"
        print(f"{addr:#08x}: {raw:<8} {mn:<8} {ops}{ann}")
        n += 1
        if args.end is None and n >= args.count:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
