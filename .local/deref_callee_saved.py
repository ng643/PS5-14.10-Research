
import json,struct
from capstone import *
from capstone.x86 import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
idx=json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
bodies={}
for e in idx["entries"]:
    th=int(e["sy_call"],16)-BASE
    rel=struct.unpack_from("<i",img,th+1)[0]
    bodies.setdefault(th+5+rel,[]).append(e["num"])
CALLEE={"rbx","rbp","r12","r13","r14","r15"}
def regs_of(op):
    out=[]
    if op.type==X86_OP_REG: out.append(ins_reg(op.reg))
    return out
res=[]
for b,nums in sorted(bodies.items()):
    t={}            # reg -> 'UAP' | 'VAL'
    stk={}          # rbp offset -> 'UAP' | 'VAL'
    hits=[]
    n=0
    for ins in md.disasm(img[b:b+0x1800],b):
        n+=1
        if n>500: break
        if ins.mnemonic in ("ret","jmp") and ins.mnemonic=="ret": break
        mn=ins.mnemonic; ops=ins.operands
        # memory reads whose base/index is tainted VAL -> candidate
        for o in ops:
            if o.type==X86_OP_MEM:
                base=ins.reg_name(o.mem.base) if o.mem.base else ""
                ix=ins.reg_name(o.mem.index) if o.mem.index else ""
                if t.get(base)=="VAL" or t.get(ix)=="VAL":
                    hits.append((ins.address-BASE,ins.mnemonic,ins.op_str,base,ix))
        if mn=="call":
            for r in list(t):
                if r not in CALLEE: t.pop(r,None)
            continue
        if mn=="mov" and len(ops)==2:
            d,s=ops
            if d.type==X86_OP_REG:
                dn=ins.reg_name(d.reg)
                if s.type==X86_OP_REG:
                    t[dn]=t.get(ins.reg_name(s.reg))
                elif s.type==X86_OP_MEM:
                    bn=ins.reg_name(s.mem.base) if s.mem.base else ""
                    if bn=="rsi" and t.get("rsi")=="UAP": t[dn]="VAL"
                    elif t.get(bn)=="VAL": t[dn]="VAL"
                    elif bn=="rbp" and s.mem.disp in stk: t[dn]=stk[s.mem.disp]
                    else: t[dn]=None
                else: t[dn]=None
            elif d.type==X86_OP_MEM and s.type==X86_OP_REG:
                bn=ins.reg_name(d.mem.base) if d.mem.base else ""
                if bn=="rbp": stk[d.mem.disp]=t.get(ins.reg_name(s.reg))
        elif mn=="lea" and len(ops)==2 and ops[0].type==X86_OP_REG:
            dn=ins.reg_name(ops[0].reg)
            s=ops[1]
            if s.type==X86_OP_MEM:
                bn=ins.reg_name(s.mem.base) if s.mem.base else ""
                t[dn]="UAP" if (bn=="rsi" and t.get("rsi")=="UAP") else t.get(bn)
            else: t[dn]=None
        elif ops and ops[0].type==X86_OP_REG:
            dn=ins.reg_name(ops[0].reg)
            if mn in ("xor","sub") and len(ops)==2 and ops[1].type==X86_OP_REG and ins.reg_name(ops[1].reg)==dn:
                t[dn]=None
            elif mn in ("add","sub","and","or","shl","shr","sar","imul","inc","dec","neg","not","movzx","movsxd","movsx","cdqe","test"):
                if len(ops)==2 and ops[1].type==X86_OP_REG and ins.reg_name(ops[1].reg)==dn:
                    pass
                elif dn in t: pass
                else: t[dn]=None
    if hits:
        res.append((b,nums,hits))
print("bodies with a deref of a uap-derived value:",len(res))
for b,nums,hits in res:
    print("  body 0x%06X sys %s"%(b,",".join(map(str,nums[:4]))))
    for a,m,o,ba,ix in hits[:4]:
        print("      0x%06X %s %s   (base=%s idx=%s)"%(a,m,o,ba,ix))

