
import struct
from capstone import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def show(a,b):
    for ins in md.disasm(img[a:b],BASE+a):
        print("  %08x  %-24s %s %s"%(ins.address-BASE,ins.bytes.hex(),ins.mnemonic,ins.op_str))
print("-- fn 0x55f010 head --")
show(0x55f010,0x55f040)
print("-- callers of 0x55f010 (call rel32) --")
T=BASE+0x55f010
for i in range(len(img)-5):
    if img[i]==0xe8:
        if BASE+i+5+struct.unpack_from("<i",img,i+1)[0]==T: print("   call at 0x%06x"%i)
print("-- body 0x55ed70 head 0x40 --")
show(0x55ed70,0x55edb0)

