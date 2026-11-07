
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
def window(fstart,lo,hi,span=0x900):
    lst=list(md.disasm(IMG[fstart:fstart+span],BASE+fstart))
    print('===== %x window %x-%x (%d ins) ====='%(fstart,lo,hi,len(lst)))
    for i in lst:
        a=i.address-BASE
        if lo<=a<hi: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
window(0x4f6b70,0x4f6e20,0x4f6f20)
window(0xb2c8e0,0xb2ca10,0xb2cb40,0xa00)
