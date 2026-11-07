
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
W(0xabc710,0xabc892,0xabc9f6,'607 tail-to-copyout')
