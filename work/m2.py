
import json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def show(rva,n=40):
    a=rva
    for _ in range(n):
        i=next(md.disasm(IMG[a:a+16],BASE+a,1),None)
        if not i: break
        print('%08x %-20s %s %s' % (a,i.bytes.hex(),i.mnemonic,i.op_str))
        a+=i.size
        if i.mnemonic=='ret': break
print('=== memcpy 0x2590b0 ===')
show(0x2590b0,40)
print('=== copyin 0x259280 ===')
show(0x259280,30)
se=json.load(open(D+r'\sysent_index.json'))['entries']
rows=[]
for e in se:
    off=int(e['sy_call_off'],16); b=IMG[off:off+5]
    if b[0]==0xe9:
        rel=int.from_bytes(b[1:5],'little',signed=True); rows.append((off+5+rel,e['num'],e['narg']))
rows.sort()
print('--- bodies 0x3b2000..0x3b9000 ---')
for t,n,na in rows:
    if 0x3b2000<=t<=0x3b9000: print('%7x num=%d narg=%d'%(t,n,na))
