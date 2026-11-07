
import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
BASE=0xffffffff8a9c0000
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
se=json.load(open(D+r'\sysent_index.json'))['entries']
rows=[]
for e in se:
    off=int(e['sy_call_off'],16); b=IMG[off:off+5]
    if b[0]==0xe9:
        rel=int.from_bytes(b[1:5],'little',signed=True); tgt=off+5+rel
        rows.append((tgt,e['num'],e['narg']))
rows.sort()
for tgt,num,narg in rows:
    if 0xab0000 <= tgt <= 0xac1000:
        print('%7x  num=%3d narg=%d' % (tgt,num,narg))
print('--- prologues in 0xabe800..0xabf200 ---')
import re
for a in range(0xabe800,0xabf200):
    if IMG[a:a+4]==b'\x55\x48\x89\xe5':
        print('prologue %x' % a)
