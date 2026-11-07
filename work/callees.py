
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
for rva,n in ((0x4f6b70,44),(0xb2c8e0,44),(0x9fcf00,20),(0x4f6700,30)):
    print('===== %x ====='%rva)
    for i in md.disasm(IMG[rva:rva+0x140],BASE+rva):
        print('%08x %-8s %s'%(i.address-BASE,i.mnemonic,i.op_str))
        n-=1
        if n<=0: break
