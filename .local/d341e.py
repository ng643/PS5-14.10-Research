
import struct,json
from capstone import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def show(a,b,label):
    print("-- %s --"%label)
    for ins in md.disasm(img[a:b],BASE+a):
        print("  %08x  %-22s %s %s"%(ins.address-BASE,ins.bytes.hex(),ins.mnemonic,ins.op_str))
show(0x55c920,0x55c9a0,"iterator 0x55c920 head")
def callers(t):
    T=BASE+t; out=[]
    for i in range(len(img)-5):
        if img[i]==0xe8 and BASE+i+5+struct.unpack_from("<i",img,i+1)[0]==T: out.append(i)
    return out
print("callers of 0x55c920:",[hex(x) for x in callers(0x55c920)][:10])
print("callers of 0x55f010:",[hex(x) for x in callers(0x55f010)])
# does anything take the ADDRESS of 0x55f010 (lea rip / mov imm64)?
T=struct.pack("<Q",BASE+0x55f010)
print("absolute qword refs to 0x55f010:",[hex(i) for i in range(len(img)-8) if img[i:i+8]==T][:5])

