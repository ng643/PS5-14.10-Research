
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
print('len',hex(len(IMG)))
md=Cs(CS_ARCH_X86,CS_MODE_64)
chunk=IMG[0x4f6e00:0x4f6f80]
print('chunk',len(chunk),chunk[:8].hex())
lst=list(md.disasm(chunk,BASE+0x4f6e00))
print('n',len(lst))
for i in lst[:20]: print('%08x %s %s'%(i.address-BASE,i.mnemonic,i.op_str))
