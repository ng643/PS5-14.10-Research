
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
BASE=0xffffffff8a9c0000
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def walk(start, limit=0x800):
    seen={}; work=[start]
    while work:
        a=work.pop()
        while a is not None and start<=a<start+limit:
            if a in seen: break
            ins=next(md.disasm(IMG[a:a+16],BASE+a,1),None)
            if ins is None: break
            seen[a]=ins; m=ins.mnemonic
            if m in ('ret','ud2'): break
            if m=='jmp' and ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=(ins.operands[0].imm&0xffffffffffffffff)-BASE
                if start<=t<start+limit: a=t; continue
                break
            if m.startswith('j') and ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=(ins.operands[0].imm&0xffffffffffffffff)-BASE
                if start<=t<start+limit: work.append(t)
            a=a+ins.size
    return [seen[k] for k in sorted(seen)]
ins=walk(0xabccc0,0x600)
print(len(ins))
for i in ins[60:]:
    print('%08x %-16s %-7s %s'%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
