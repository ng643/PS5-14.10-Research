import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE = 0xffffffff8a9c0000
img = open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
N = len(img)
def i32(o): return struct.unpack_from("<i", img, o)[0]
def u64(o): return struct.unpack_from("<Q", img, o)[0]

helpers = list(range(0x609020, 0x609530, 0x20)) + list(range(0x609720, 0x609A00, 0x20))
hset = set(helpers)
md = Cs(CS_ARCH_X86, CS_MODE_64)

def tag_of(h):
    # movabs rcx, imm64 is 48 B9 <imm64>
    for k in range(h, h+0x30):
        if img[k] == 0x48 and img[k+1] == 0xb9:
            return u64(k+2)
    return None

sites = []
for i in range(N-5):
    if img[i] != 0xe8: continue
    tgt = i + 5 + i32(i+1)
    if tgt in hset: sites.append((i, tgt))

for off, tgt in sites:
    s = max(0, off-40)
    insns = list(md.disasm(img[s:off], BASE+s))
    src = None
    for ins in reversed(insns):
        if ins.mnemonic.startswith("mov") and ins.op_str.startswith("rdi,"):
            src = ins.op_str; break
        if ins.mnemonic in ("call","ret","jmp"): break
    if src and "+ 0x40]" in src:
        print("site %08X -> helper %08X tag %016X   %s" % (off, tgt, tag_of(tgt) or 0, src))
        for ins in insns[-6:]:
            print("      %08X  %-8s %s" % (ins.address-BASE, ins.mnemonic, ins.op_str))
        print("")
