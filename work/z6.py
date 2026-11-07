
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64)
md.detail=True
targets={642:0xabdad0,618:0xabd0f0,607:0xabc710,734:0xfc890,727:0x3b3090,728:0xabb660,721:0x6444d0,608:0x34bdc0,641:0x4a2de0,667:0x4a31a0,627:0x4a2850}
def dump(num,base,span=0x800):
    lst=list(md.disasm(IMG[base:base+span],BASE+base))
    print('\n########## %d @ %x  (%d ins decoded) ##########'%(num,base,len(lst)))
    n=0
    for i in lst:
        a=i.address-BASE
        if i.mnemonic=='ret' :
            print('%08x ret'%a); n+=1
            if n>2: break
            continue
        hit=False
        if i.mnemonic=='call': hit=True
        if 'rsi' in i.op_str and ('[' in i.op_str): hit=True
        if i.mnemonic in ('mov','movsxd','movzx','movsx') and i.op_str.startswith(('eax','rax','dword ptr [rbp','qword ptr [rbp')) and 'rsi' not in i.op_str: hit=False
        if i.mnemonic.startswith('j') and i.mnemonic!='jmp': hit=True
        if hit: print('%08x %-7s %s'%(a,i.mnemonic,i.op_str))
for k in sorted(targets): dump(k,targets[k])
