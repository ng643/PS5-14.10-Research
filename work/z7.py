
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
def W(fstart,lo,hi,span=0x600,lbl=''):
    lst=list(md.disasm(IMG[fstart:fstart+span],BASE+fstart))
    print('\n===== %s  %x-%x ====='%(lbl,lo,hi))
    for i in lst:
        a=i.address-BASE
        if lo<=a<hi: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
W(0x34bdc0,0x34c1d0,0x34c290,0x600,'608 tail')
W(0xabdad0,0xabe000,0xabe170,0x700,'642 copyout')
