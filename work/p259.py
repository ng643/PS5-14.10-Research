
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
for rva,n in ((0x2591d0,40),(0x259280,40)):
    print('===== %x ====='%rva)
    for i in md.disasm(IMG[rva:rva+0xc0],BASE+rva):
        print('%08x %-8s %s'%(i.address-BASE,i.mnemonic,i.op_str))
        n-=1
        if n<=0: break
