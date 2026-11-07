
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
BASE=0xffffffff8a9c0000
IMG=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
TARGETS={0x2591d0:'copyout',0x259280:'copyin',0x2590b0:'memcpy',0x259900:'copyinstr',0x2599f0:'copystr_k',0x259720:'suword64',0x259790:'suword32'}
def scan(start,end):
    print('===== scan %x-%x ====='%(start,end))
    lst=list(md.disasm(IMG[start:end],BASE+start))
    for i,ins in enumerate(lst):
        if ins.mnemonic=='call':
            t=ins.operands[0]
            if t.type==X86_OP_IMM:
                tv=(t.imm&0xffffffffffffffff)-BASE
                if tv in TARGETS:
                    print('--- %s at %08x ---'%(TARGETS[tv],ins.address-BASE))
                    for k in range(max(0,i-9),min(len(lst),i+4)):
                        print('   %08x %-7s %s'%(lst[k].address-BASE,lst[k].mnemonic,lst[k].op_str))
scan(0x4f6b70,0x4f7100)
scan(0xb2c8e0,0xb2cf00)
scan(0x4f7940,0x4f7a00)
