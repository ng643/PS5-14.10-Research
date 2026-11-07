
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
for start,end in ((0x4f6e00,0x4f6f80),(0xb2ca10,0xb2cb40)):
    print('===== %x ====='%start)
    for i in md.disasm(IMG[start:end],BASE+start):
        print('%08x %-7s %s'%(i.address-BASE,i.mnemonic,i.op_str))
