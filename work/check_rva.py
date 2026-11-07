
import json, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

BASE = 0xffffffff8a9c0000
D = r'C:\PS5contrib\docs\dumps_13.60'
IMG = open(D + r'\kernel_text.bin','rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

sysent = {e['num']: e for e in json.load(open(D + r'\sysent_index.json'))['entries']}
print('max num', max(sysent))
req = [(646,0xabe1c0),(647,0xabe7b0),(642,0xabdad0),(618,0xabd0f0),(624,0xabd4f0),(733,0xabd000),
       (734,0xfc890),(727,0x3b3090),(728,0xabb660),(671,0xabe8b0),(675,0x2d36f0),(705,0x2d3730),
       (721,0x6444d0),(611,0xa36bc0),(612,0x34ce50),(613,0xabca10),(615,0xabcc00),(604,0x4f7370),
       (607,0xabc710),(608,0x34bdc0),(641,0x4a2de0),(667,0x4a31a0),(717,0x4f7250),(724,0x4f7940),
       (627,0x4a2850),(308,0x552cb0)]
for num, rva in req:
    e = sysent.get(num)
    tgt = None
    if e:
        off = int(e['sy_call_off'],16)
        b = IMG[off:off+5]
        if b[0] == 0xe9:
            rel = int.from_bytes(b[1:5],'little',signed=True)
            tgt = off + 5 + rel
    print(num, hex(rva), 'sysent_body=', hex(tgt) if tgt is not None else None,
          'match' if tgt==rva else ('MISMATCH narg='+str(e['narg']) if e else 'not in sysent'))
