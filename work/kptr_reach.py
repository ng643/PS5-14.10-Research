
import json, os, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_MEM, CS_OP_IMM
import capstone.x86 as X86

ROOT = r"C:\PS5contrib"
DUMPS = os.path.join(ROOT, "docs", "dumps_13.60")
TEXT = open(os.path.join(DUMPS, "kernel_text.bin"), "rb").read()
TEXT_SIZE = len(TEXT)
BASE = 0xffffffff8a9c0000
COPYOUT = 0x2591d0
COPYIN  = 0x259280
TEXT_LIMIT = 0xcc0000  # .text end per local layout analysis

syent = {e["num"]: e for e in json.load(open(os.path.join(DUMPS, "sysent_index.json")))["entries"]}

def thunk_target(off):
    off = int(off, 16) if isinstance(off, str) else int(off)
    if off + 5 > TEXT_SIZE: return None
    if TEXT[off] != 0xE9: return None
    rel = struct.unpack("<i", TEXT[off+1:off+5])[0]
    return off + 5 + rel

_md = Cs(CS_ARCH_X86, CS_MODE_64); _md.detail = True
REGS = {r: _md.reg_name(r) for r in range(0, 300)}

def disasm(rva, size):
    out = []
    end = min(rva+size, TEXT_SIZE)
    pos = rva
    while pos < end:
        chunk = TEXT[pos:min(pos+65536, end)]
        got = 0
        for i in _md.disasm(chunk, BASE+pos):
            out.append(i); got += 1
        if got == 0:
            pos += 1; continue
        nxt = out[-1].address - BASE + out[-1].size
        pos = nxt if nxt > pos else pos+1
    return out

def estimate_size(rva, max_size=0x20000):
    end = min(rva + max_size, TEXT_SIZE)
    i = rva + 0x10; run = 0
    while i < end:
        b = TEXT[i]
        if b in (0xCC, 0x90):
            run += 1
            if run >= 12: return i - run - rva
        else:
            run = 0
        i += 1
    return max_size

def wr_regs(insn):
    """registers written by this insn (x86, simplified)"""
    out = set()
    for op in insn.operands:
        if op.type == CS_OP_REG and op.access & 2:  # CS_AC_WRITE == 2
            out.add(_md.reg_name(op.reg))
    # implicit writes
    for r in insn.regs_access()[1]:
        out.add(_md.reg_name(r))
    return out

def mem_str(op):
    m = op.mem
    base = _md.reg_name(m.base) if m.base else ""
    idx = _md.reg_name(m.index) if m.index else ""
    s = ""
    if base: s += base
    if idx: s += ("+" if s else "") + idx + ("*%d" % m.scale if m.scale != 1 else "")
    if m.disp:
        s += ("%+#x" % m.disp) if m.disp else ""
    return s or "?"

def src_desc(insn):
    """describe the source operand of mov/lea as ('mem', 'reg+off') or ('reg', name) etc."""
    if not insn.operands: return ("none", "")
    op = insn.operands[1]
    if op.type == CS_OP_MEM: return ("mem", mem_str(op))
    if op.type == CS_OP_REG: return ("reg", _md.reg_name(op.reg))
    if op.type == CS_OP_IMM: return ("imm", "%#x" % (op.imm & 0xffffffffffffffff))
    return ("?", "")

def classify(insns, idx, reg="rdi", depth=0, seen=None):
    """walk back from insns[idx] (a call) to find provenance of 'reg'"""
    if seen is None: seen = set()
    if depth > 4: return ("UNKNOWN", "depth", None)
    for j in range(idx-1, max(0, idx-200), -1):
        ins = insns[j]
        # stop at control flow boundaries that make backward walking unsound
        if ins.mnemonic in ("ret", "jmp") or (ins.mnemonic.startswith("j") and ins.mnemonic != "jmp"):
            return ("UNKNOWN", "boundary@"+hex(ins.address-BASE), ins.address-BASE)
        w = wr_regs(ins)
        if reg not in w: continue
        m = ins.mnemonic
        if m in ("mov", "movzx", "movsxd", "movsx"):
            t = src_desc(ins)
            if t[0] == "mem":
                base = t[1].split("+")[0].split("*")[0]
                if base in ("rbp", "rsp"):
                    return ("STACK", t[1], ins.address-BASE)
                return ("OBJECT", t[1], ins.address-BASE)
            if t[0] == "reg":
                if t[1] in seen: return ("CYCLE", t[1], ins.address-BASE)
                seen.add(t[1])
                return classify(insns, j, t[1], depth+1, seen)
            return ("IMM", t[1], ins.address-BASE)
        if m == "lea":
            t = src_desc(ins)
            if t[0] == "mem":
                base = t[1].split("+")[0].split("*")[0]
                if base in ("rbp", "rsp"): return ("STACK", t[1], ins.address-BASE)
                return ("LEA-GLOBAL", t[1], ins.address-BASE)
            return ("LEA-OTHER", t[1], ins.address-BASE)
        if m == "pop":
            return ("POP", "", ins.address-BASE)
        if m in ("xor", "sub", "and") and len(ins.operands) == 2 and ins.operands[0].type == CS_OP_REG \
           and ins.operands[1].type == CS_OP_REG and ins.operands[0].reg == ins.operands[1].reg:
            return ("ZERO", "", ins.address-BASE)
        if m in ("add","sub","imul","or","and","shl","shr","sar","neg","not","inc","dec"):
            return ("ARITH", m, ins.address-BASE)
        if m in ("call",):
            return ("CALL-RET", "", ins.address-BASE)
        return ("OTHER:"+m, "", ins.address-BASE)
    return ("UNKNOWN", "?", None)

def sites_for(entry, size):
    insns = disasm(entry, size)
    sites = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == CS_OP_IMM:
            tgt = (ins.operands[0].imm & 0xffffffffffffffff) - BASE
            if tgt in (COPYOUT, COPYIN):
                kind = "copyout" if tgt == COPYOUT else "copyin"
                sites.append((kind, ins.address-BASE, classify(insns, idx)))
    return sites

if __name__ == "__main__":
    report = {}
    for num in range(532, 677):
        e = syent[num]; t = thunk_target(e["sy_call_off"])
        if t is None: continue
        sz = estimate_size(t)
        s = sites_for(t, sz)
        if s: report[num] = {"handler": t, "size": sz, "sites": s}
    obj = [(n, r["handler"], k, a, p) for n, r in report.items() for (k, a, p) in r["sites"] if k=="copyout" and p[0]=="OBJECT"]
    print("handlers with copyout/copyin sites: %d/145" % len(report))
    print("OBJECT copyout sites: %d" % len(obj))
    for n, h, k, a, p in sorted(obj):
        print("  sys %3d handler=%#08x site=%#08x src=[%s] set@%#x" % (n, h, a, p[1], p[2]))
    json.dump({str(n): {"handler": hex(r["handler"]), "size": r["size"],
                        "sites": [[k, hex(a), list(p)] for k,a,p in r["sites"]]} for n,r in report.items()},
              open(os.path.join(ROOT,"work","kptr_repro.json"),"w"), indent=1)