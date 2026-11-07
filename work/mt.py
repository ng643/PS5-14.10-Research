
import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
print('maxtable @0xAE6E30:')
for i in range(6):
    off=0xAE6E30+i*24
    vals=[int.from_bytes(IMG[off+k*8:off+k*8+8],'little') for k in range(3)]
    print(' idx %d: %s' % (i, [hex(v) for v in vals]))
print()
print('bytes around 0xAE6E30-0x60:', IMG[0xAE6E30:0xAE6E30+24*6].hex())
