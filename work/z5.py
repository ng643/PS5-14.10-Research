
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
lst=list(md.disasm(IMG[0x4f6b70:0x4f6b70+0x700],BASE+0x4f6b70))
for i in lst:
    a=i.address-BASE
    if 0x4f70c8<=a<0x4f7260: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
