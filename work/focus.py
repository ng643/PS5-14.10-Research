
import json, os, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
BASE=0xffffffff8a9c0000
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
DIS=r'C:\PS5contrib\work\disasm'
NAMES={0x259280:'copyin',0x2591d0:'copyout',0x2590b0:'memcpy',0x259900:'copyinstr',0x2599f0:'copystr_k',
 0x258ff0:'bzero',0x259190:'memsetw',0x259360:'casuword32',0xadfa30:'priv_check',0x259790:'suword32',
 0x608f90:'cap608f90',0x608fb0:'cap608fb0',0x609080:'cap609080',0x6091d0:'cap6091d0',0x609620:'cap609620',
 0x609750:'cap609750',0x609270:'cap609270',0x608ff0:'cap608ff0'}
def load(num):
    p=[f for f in os.listdir(DIS) if f.startswith('%d_'%num)][0]
    lines=open(os.path.join(DIS,p)).read().splitlines()
    out=[]
    for ln in lines:
        parts=ln.split(None,2)
        addr=int(parts[0],16); mn=parts[1]; ops=parts[2] if len(parts)>2 else ''
        out.append((addr,mn,ops))
    return out
def interesting(num):
    ins=load(num)
    keep=set()
    for i,(a,m,o) in enumerate(ins):
        if '[rsi' in o or 'gs:' in o or m=='call' or 'copy' in o or 'rip' in o.lower():
            for k in range(max(0,i-6), min(len(ins),i+3)): keep.add(k)
    res=[]
    prev=-2
    for i in sorted(keep):
        if i!=prev+1: res.append('   ...')
        a,m,o=ins[i]
        res.append('%08x %-8s %s'%(a,m,o))
        prev=i
    return res
for num in (611,612,613,604,607):
    print('########## %d ##########'%num)
    print('\n'.join(interesting(num)))
    print()
