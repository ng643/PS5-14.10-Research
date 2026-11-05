
import json,struct
from capstone import *
from capstone.x86 import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def dis(a,b): return list(md.disasm(img[a:b],a))
TARGETS={0xab9f60:"mmap:insert-wrapper",0x2d2e50:"mmap:apply",0x4aee40:"mmap:?",0x782a80:"mmap:?2",0xacc9a0:"mmap:?",0x2bc220:"mmap:?",0x2bc300:"mmap:?",0x72e150:"mmap:?",0xabea20:"mmap:?"}
def calls(lo,hi):
    for ins in dis(lo,hi):
        if ins.mnemonic in ("call",):
            if ins.operands[0].type==X86_OP_IMM:
                t=ins.operands[0].imm & 0xffffffffffffffff
                yield (ins.address,t-BASE)
            else:
                yield (ins.address,None)
print("=== blockpool 0x9a6c00-0x9a7d10 ===")
for a,t in calls(0x9a6c00,0x9a7d10):
    tag=TARGETS.get(t,"")
    print("  0x%06X call -> %s %s"%(a,("0x%06X"%t) if t is not None else "INDIRECT",tag))
print()
print("=== blockpool 0x9a7f00-0x9a9560 ===")
for a,t in calls(0x9a7f00,0x9a9560):
    tag=TARGETS.get(t,"")
    print("  0x%06X call -> %s %s"%(a,("0x%06X"%t) if t is not None else "INDIRECT",tag))

