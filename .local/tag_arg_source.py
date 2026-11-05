import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE = 0xffffffff8a9c0000
img = open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
N = len(img)
def i32(o): return struct.unpack_from("<i", img, o)[0]

helpers = list(range(0x609020, 0x609530, 0x20)) + list(range(0x609720, 0x609A00, 0x20))
hset = set(helpers)
sites = []
for i in range(N-5):
    if img[i] != 0xe8: continue
    tgt = i + 5 + i32(i+1)
    if tgt in hset:
        sites.append((i, tgt))
print("call sites to tag helpers:", len(sites))

md = Cs(CS_ARCH_X86, CS_MODE_64)
from collections import Counter
disp = Counter()
noreg = 0
for off, tgt in sites:
    s = max(0, off-40)
    insns = list(md.disasm(img[s:off], BASE+s))
    src = None
    for ins in reversed(insns):
        if ins.mnemonic.startswith("mov") and ins.op_str.startswith("rdi,"):
            src = ins.op_str; break
        if ins.mnemonic in ("call","ret","jmp"): break
    if src is None:
        noreg += 1; continue
    disp[src.split(",")[1].strip()] += 1
print("no explicit rdi load (inherited):", noreg)
for k, v in disp.most_common(12):
    print("   rdi <- %-28s %d" % (k, v))
