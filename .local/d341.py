
import struct
from capstone import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def off(a): return a-BASE
# 1. branch targets landing on 0x55f0cb
T=0xffffffff8a9c0000+0x55f0cb
hits=[]
for i in range(0,len(img)-6):
    b=img[i]
    if b in (0xe8,0xe9):
        rel=struct.unpack_from("<i",img,i+1)[0]
        if BASE+i+5+rel==T: hits.append((hex(BASE+i),"call" if b==0xe8 else "jmp"))
print("direct branches to 0x55f0cb:",hits)
# 2. prologues between 0x55e800 and 0x55f0cb
print("\n-- prologue candidates (55 48 89 e5) in 0x55e800..0x55f0cb --")
for i in range(0x55e800,0x55f0cb):
    if img[i:i+4]==b"\x55\x48\x89\xe5":
        print("  0x%06x"%i)
# 3. listing 0x55f040 .. 0x55f100
print("\n-- listing 0x55f040..0x55f110 --")
start=0x55f040
for ins in md.disasm(img[start:0x55f110],BASE+start):
    print("  %08x  %-28s %s %s"%(ins.address-BASE,ins.bytes.hex(),ins.mnemonic,ins.op_str))

