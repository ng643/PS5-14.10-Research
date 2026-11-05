
import struct,json
from capstone import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def show(a,b,label):
    print("-- %s --"%label)
    for ins in md.disasm(img[a:b],BASE+a):
        print("  %08x  %-22s %s %s"%(ins.address-BASE,ins.bytes.hex(),ins.mnemonic,ins.op_str))
show(0x4ea560,0x4ea5c0,"caller 0x4ea5ae context")
def callers(t):
    T=BASE+t; out=[]
    for i in range(len(img)-5):
        if img[i]==0xe8 and BASE+i+5+struct.unpack_from("<i",img,i+1)[0]==T: out.append(i)
    return out
for t in (0x4ea300,0x55f010,0x55f1c920):
    print("callers of 0x%06x: %s"%(t,[hex(x) for x in callers(t)][:12]))
# which enclosing functions (prologue before) contain those call sites
def enclosing(a):
    i=a
    while i>a-0x4000 and i>0:
        if img[i:i+4]==b"\x55\x48\x89\xe5": return i
        i-=1
    return None
for t in (0x4ea300,0x55f1c920):
    for c in callers(t)[:12]:
        print("   0x%06x called from fn 0x%06x"%(t,enclosing(c) or -1))

