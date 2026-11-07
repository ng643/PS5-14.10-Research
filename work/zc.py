
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
def W(f,lo,hi,lbl,span=0x500):
    lst=list(md.disasm(IMG[f:f+span],BASE+f))
    print('\n===== %s ====='%lbl)
    for i in lst:
        a=i.address-BASE
        if lo<=a<hi: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
W(0x3b3090,0x3b3300,0x3b33a0,'727 indexed uap')
W(0xabd0f0,0xabd280,0xabd3f0,'618 body')
W(0x6444d0,0x6444e0,0x6445a0,'721 cases')
