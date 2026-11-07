
import sys, re
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = False

prev = {}
hits = []
pos = 0; END = 0xcc0000
while pos < END:
    chunk = K.TEXT[pos:min(pos+65536, END)]
    last = None
    for i in md.disasm(chunk, pos):
        ops = i.op_str
        if i.mnemonic == "mov" and ops.startswith("qword ptr [") and " 0x148], " in ops:
            m = re.match(r"qword ptr \[(\w+)(?: \+ (0x[0-9a-f]+))?\], (\w+)", ops)
            if m and m.group(1) not in ("rbp","rsp"):
                hits.append((i.address, m.group(1), m.group(3), last))
        last = (i.address, i.mnemonic, i.op_str)
    pos += 65536
print("stores to [reg+0x148]:", len(hits))
for a, base, src, last in hits:
    ls = "%#x %s %s" % last if last else "-"
    print("  %#08x [%s+0x148]=%s   prev: %s" % (a, base, src, ls))
