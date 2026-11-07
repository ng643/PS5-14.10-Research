
import sys, re, json
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

hits = []
pos = 0
END = 0xcc0000
while pos < END:
    chunk = K.TEXT[pos:min(pos+65536, END)]
    for i in md.disasm(chunk, pos):
        ops = i.op_str
        if i.mnemonic == "mov" and ops.startswith("qword ptr [") and "], " in ops:
            m = re.match(r"qword ptr \[(\w+)(?: \+ (0x[0-9a-f]+))?\], (\w+)", ops)
            if m:
                base, disp, src = m.group(1), m.group(2), m.group(3)
                if base in ("rbp","rsp"): continue
                if disp in ("0x88","0x90"):
                    hits.append((i.address, base, disp, src))
    pos += 65536
print("raw hits", len(hits))
# group: same base register within +-0x400 bytes, one at 0x88 and one at 0x90
by = {}
for a, b, d, s in hits:
    by.setdefault((b, a >> 12), []).append((a, b, d, s))
out = []
for k, v in by.items():
    d88 = [x for x in v if x[2]=="0x88"]
    d90 = [x for x in v if x[2]=="0x90"]
    for x in d88:
        for y in d90:
            if 0 < y[0]-x[0] < 0x200:
                out.append((x[0], y[0], x[1], x[3], y[3]))
print("pairs (0x88 store then 0x90 store within 0x200):", len(out))
for a,b,reg,s1,s2 in sorted(out)[:40]:
    print("  %#08x/%#08x base=%s  [%s+0x88]=%s  [%s+0x90]=%s" % (a,b,reg,reg,s1,reg,s2))
