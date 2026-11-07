
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K

def find_func(addr, maxback=0x4000):
    cands = []
    start = max(0, addr-maxback)
    i = start
    while i < addr:
        # candidate prologue patterns
        if K.TEXT[i] == 0x55 and K.TEXT[i+1:i+4] == b"\x48\x89\xe5":
            cands.append(i)
            i += 4; continue
        if K.TEXT[i] == 0xF3 and K.TEXT[i+1:i+4] == b"\x0f\x1e\xfa":
            cands.append(i); i += 4; continue
        i += 1
    # pick the latest candidate whose linear disasm covers addr
    for c in reversed(cands):
        insns = K.disasm(c, addr-c+32)
        addrs = [x.address-K.BASE for x in insns]
        if addr in addrs:
            return c, insns
    return None, None

sites = [0x4f757f, 0x34b8e2, 0xca1b8b, 0x34c647, 0x34bd8e, 0x3b018a, 0x3b1612, 0x3b1f6d]
for s in sites:
    f, insns = find_func(s)
    print("site %#08x -> func %s  insns=%s  span=%s" % (s, hex(f) if f else None, len(insns) if insns else 0,
          hex(insns[-1].address-K.BASE) if insns else "-"))
