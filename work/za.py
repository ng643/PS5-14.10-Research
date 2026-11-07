
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
def W(f,lo,hi,lbl,span=0x600):
    lst=list(md.disasm(IMG[f:f+span],BASE+f))
    print('\n===== %s ====='%lbl)
    for i in lst:
        a=i.address-BASE
        if lo<=a<hi: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
W(0x4a2de0,0x4a3060,0x4a31a0,'641 tail')
W(0xabc710,0xabc710,0xabc8a0,'607 head')
