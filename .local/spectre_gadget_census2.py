import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

BASE = 0xffffffff8a9c0000
img = open(r"C:\\PS5contrib\\docs\\dumps_13.60\\kernel_text.bin","rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
md.skipdata = True

insns = list(md.disasm(img, BASE))
print("decoded", len(insns))

def mem_op(ins):
    for o in ins.operands:
        if o.type == X86_OP_MEM: return o
    return None

def is_indexed_load(ins):
    if not ins.mnemonic.startswith(("mov","movzx","movsx","movsxd")): return None
    if len(ins.operands) < 2: return None
    if ins.operands[0].type != X86_OP_REG: return None
    m = ins.operands[1]
    if m.type != X86_OP_MEM: return None
    if m.mem.index == 0: return None
    return ins.operands[0].reg, m

def reg_name(ins, rid):
    return ins.reg_name(rid)

def same_reg(ins, a, b):
    # compare 32-bit halves of the same architectural register
    na, nb = ins.reg_name(a), ins.reg_name(b)
    if na is None or nb is None: return False
    canon = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi","ebp":"rbp","esp":"rsp"}
    return canon.get(na, na) == canon.get(nb, nb)

cands = []
n = len(insns)
for i, ins in enumerate(insns):
    ld = is_indexed_load(ins)
    if not ld: continue
    dreg, m = ld
    # next 1..3 instructions must shift dreg
    for j in range(i+1, min(i+4, n)):
        s = insns[j]
        if s.mnemonic not in ("shl","sal"): 
            if s.mnemonic == "and": continue
            break
        if s.mnemonic == "and":
            continue
        if len(s.operands) < 2: break
        if s.operands[0].type != X86_OP_REG: break
        if not same_reg(s, s.operands[0].reg, dreg): break
        if s.operands[1].type != X86_OP_IMM: break
        k = s.operands[1].imm
        if k < 6 or k > 12: break
        # next 1..3: store with dreg as index
        for t in range(j+1, min(j+4, n)):
            st = insns[t]
            if not st.mnemonic.startswith("mov"): 
                if st.mnemonic in ("lea",): continue
                break
            mo = None
            for o in st.operands:
                if o.type == X86_OP_MEM: mo = o
            if mo is None: break
            if mo.mem.index == 0: break
            if not same_reg(st, mo.mem.index, dreg): break
            cands.append((ins, s, st, k))
            break
        break

print("strict chain candidates:", len(cands))
for ins, s, st, k in cands[:40]:
    print("  %016X  %-40s | %-14s | %s" % (ins.address, ins.mnemonic+" "+ins.op_str, s.mnemonic+" "+s.op_str, st.mnemonic+" "+st.op_str))
