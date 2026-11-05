
import struct
from capstone import *
from capstone.x86 import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
MMAP={0xab9f60:"mmap:insert",0x2d2e50:"mmap:apply",0x4aee40:"mmap:4aee40",0x782a80:"mmap:782a80",0xacc9a0:"mmap:acc9a0",0x2bc220:"mmap:2bc220",0x2bc300:"mmap:2bc300",0x72e150:"mmap:72e150",0xabea20:"mmap:abea20",0x6fd6b0:"mmap:6fd6b0"}
def calls(lo,hi):
    for ins in md.disasm(img[lo:hi],lo):
        if ins.mnemonic=="call":
            if ins.operands[0].type==X86_OP_IMM:
                yield (ins.address, ins.operands[0].imm & 0xffffffffffffffff)
            else:
                yield (ins.address, None)
hits=[]
for lo,hi in ((0x9a6c00,0x9a7d10),(0x9a7f00,0x9a9560)):
    for a,t in calls(lo,hi):
        if t in MMAP: hits.append((a,t,MMAP[t]))
print("blockpool calls into mmap helpers:",len(hits))
for a,t,n in hits: print("  0x%06X -> 0x%06X  %s"%(a,t,n))
print()
# also: does anything in the blockpool region reference the insert helper at all
for name,t in ((n,t) for t,n in [(k,v) for k,v in MMAP.items()]):
    pass
print("=== unique call targets in 0x9a6c00-0x9a9560 (count) ===")
seen={}
for lo,hi in ((0x9a6c00,0x9a7d10),(0x9a7f00,0x9a9560)):
    for a,t in calls(lo,hi):
        if t is not None: seen[t]=seen.get(t,0)+1
print("distinct:",len(seen))
for t in sorted(seen): print("  0x%06X x%d"%(t,seen[t]))

