
import sys, json
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K

TRACK = {"rdi","rsi","rdx","rax","rbx","rcx","r8","r9","r10","r11","r12","r13","r14","r15"}

def classify_up(insns, idx, depth=0, reg="rdi"):
    if depth > 3: return ("UNKNOWN", "deep:"+reg, None)
    for j in range(idx-1, max(0, idx-150), -1):
        ins = insns[j]
        m, ops = ins.mnemonic, ins.op_str
        if m == "mov" and ops.startswith(reg+","):
            src = ops[len(reg)+1:].strip()
            if src.startswith("qword ptr [") or src.startswith("["):
                inner = src[src.index("[")+1:src.rindex("]")]
                return ("OBJECT", inner, ins.address-K.BASE)
            if src in TRACK:
                r = classify_up(insns, j, depth+1, src)
                if r[0] != "UNKNOWN": return r
                return ("REG-CHAIN", src, ins.address-K.BASE)
            return ("IMM", src, ins.address-K.BASE)
        if m == "lea" and ops.startswith(reg+","):
            src = ops[len(reg)+1:].strip()
            if "rbp" in src or "rsp" in src: return ("STACK", src, ins.address-K.BASE)
            return ("LEA-GLOBAL", src, ins.address-K.BASE)
    return ("UNKNOWN", "?", None)

report = {}
for num in range(532, 677):
    e = K.syent[num]; t = K.thunk_target(e["sy_call_off"])
    if t is None: continue
    sz = K.estimate_size(t)
    insns = K.disasm(t, sz)
    sites = []
    for idx, ins in enumerate(insns):
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == K.CS_OP_IMM:
            tgt = (ins.operands[0].imm & 0xffffffffffffffff) - K.BASE
            if tgt == K.COPYOUT:
                sites.append(("copyout", ins.address-K.BASE, classify_up(insns, idx)))
            elif tgt == K.COPYIN:
                sites.append(("copyin", ins.address-K.BASE, classify_up(insns, idx)))
    if sites: report[num] = sites

obj = [(n,a,p) for n,s in report.items() for (k,a,p) in s if k=="copyout" and p[0]=="OBJECT"]
print("handlers:", len(report), "OBJECT copyout:", len(obj))
seen=set()
for n,a,p in sorted(obj):
    key=(a,p[1])
    print("  sys %3d site=%#08x src=[%s] set@%#x %s" % (n,a,p[1],p[2], "(dup)" if key in seen else ""))
    seen.add(key)
