
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
def W(f,s,lbl):
    lst=list(md.disasm(IMG[f:f+0x700],BASE+f))
    print('\n===== %s ====='%lbl)
    for i in lst:
        a=i.address-BASE
        if a<f+0x700: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
W(0x34be40,'608 mid','608 mid 34be40-34c040')
