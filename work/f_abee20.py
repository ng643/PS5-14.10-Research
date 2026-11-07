
import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
BASE=0xffffffff8a9c0000
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def walk(start, limit=0x4000):
    seen={}; work=[start]
    while work:
        a=work.pop()
        while a is not None and start<=a<start+limit:
            if a in seen: break
            ins=next(md.disasm(IMG[a:a+16],BASE+a,1),None)
            if ins is None: break
            seen[a]=ins
            m=ins.mnemonic
            if m in ('ret','ud2','iretq'): break
            if m=='jmp' and ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=(ins.operands[0].imm&0xffffffffffffffff)-BASE
                if start<=t<start+limit: a=t; continue
                break
            if m.startswith('j') and ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=(ins.operands[0].imm&0xffffffffffffffff)-BASE
                if start<=t<start+limit: work.append(t)
            a=a+ins.size
    return [seen[k] for k in sorted(seen)]

for start in (0xabee20,0xabefa4):
    ins=walk(start)
    print('=== %x (%d ins) ===' % (start,len(ins)))
    for i in ins:
        print('%08x %-20s %-7s %s' % (i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
    print()
# callers of abee20 / abefa4
for tgt,label in ((0xabee20,'abee20'),(0xabefa4,'abefa4')):
    hits=[]
    for a in range(len(IMG)-5):
        if IMG[a]==0xe8:
            rel=int.from_bytes(IMG[a+1:a+5],'little',signed=True)
            if a+5+rel==tgt: hits.append(a)
    print('callers of',label,[hex(h) for h in hits][:20])
