
import json, os, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

BASE = 0xffffffff8a9c0000
D = r'C:\PS5contrib\docs\dumps_13.60'
OUT = r'C:\PS5contrib\work\disasm'
os.makedirs(OUT, exist_ok=True)
IMG = open(D + r'\kernel_text.bin','rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

NAMES = {
 0x259280:'copyin',0x2591d0:'copyout',0x2590b0:'memcpy',0x259900:'copyinstr',0x2599f0:'copystr_k',
 0x258ff0:'bzero',0x259190:'memsetw',0x259360:'casuword32',0xadfa30:'priv_check',
 0x608f90:'cap_0x608f90',0x608fb0:'cap_0x608fb0',0x609080:'cap_0x609080',0x6091d0:'cap_0x6091d0',
 0x609620:'cap_0x609620',0x609750:'cap_0x609750',0x609270:'cap_0x609270',0x608ff0:'cap_0x608ff0',
}

def one(rva):
    ins = next(md.disasm(IMG[rva:rva+16], BASE+rva, 1), None)
    return ins

def walk(start, limit=0x3000):
    seen={}; work=[start]
    while work:
        a=work.pop()
        while a is not None and start <= a < start+limit:
            if a in seen: break
            ins = one(a)
            if ins is None:
                break
            seen[a]=ins
            m=ins.mnemonic
            if m in ('ret','ud2','iretq','int3'):
                if m=='int3':
                    nxt=IMG[a+1:a+4]
                    if all(b==0xcc for b in nxt): break
                break
            if m=='jmp' and ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=(ins.operands[0].imm & 0xffffffffffffffff)-BASE
                if start <= t < start+limit:
                    a=t; continue
                break
            if m.startswith('j') and ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=(ins.operands[0].imm & 0xffffffffffffffff)-BASE
                if start <= t < start+limit:
                    work.append(t)
            a = a + ins.size
    return [seen[k] for k in sorted(seen)]

def render(num, rva):
    ins = walk(rva)
    lines=[]
    for i in ins:
        c=''
        if i.mnemonic=='call' and i.operands and i.operands[0].type==X86_OP_IMM:
            t=((i.operands[0].imm) & 0xffffffffffffffff)-BASE
            c='   ; -> %x %s' % (t, NAMES.get(t,''))
        lines.append('%08x %-22s %-7s %s%s' % (i.address-BASE, i.bytes.hex(), i.mnemonic, i.op_str, c))
    p=os.path.join(OUT,'%d_%x.txt'%(num,rva))
    open(p,'w').write('\n'.join(lines)+'\n')
    calls = sorted({((i.operands[0].imm)&0xffffffffffffffff)-BASE for i in ins if i.mnemonic=='call' and i.operands and i.operands[0].type==X86_OP_IMM})
    return len(ins), calls

req = [(646,0xabe1c0),(647,0xabe7b0),(642,0xabdad0),(618,0xabd0f0),(624,0xabd4f0),(733,0xabd000),
       (734,0xfc890),(727,0x3b3090),(728,0xabb660),(671,0xabe8b0),(675,0x2d36f0),(705,0x2d3730),
       (721,0x6444d0),(611,0xa36bc0),(612,0x34ce50),(613,0xabca10),(615,0xabcc00),(604,0x4f7370),
       (607,0xabc710),(608,0x34bdc0),(641,0x4a2de0),(667,0x4a31a0),(717,0x4f7250),(724,0x4f7940),
       (627,0x4a2850),(308,0x552cb0)]
tot=0
for num,rva in req:
    n,calls=render(num,rva); tot+=n
    print('%4d %7x ins=%4d  calls: %s' % (num,rva,n,' '.join('%x%s'%(c,'['+NAMES[c]+']' if c in NAMES else '') for c in calls)))
print('total', tot)
