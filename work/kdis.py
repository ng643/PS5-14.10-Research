import sys
from capstone import *
BASE = 0xffffffff8a9c0000
BIN = "C:/PS5contrib/docs/dumps_13.60/kernel_text.bin"
_orig = open(BIN,"rb").read()
def dis(rva, length, lo=None, hi=None):
    code = _orig[rva:rva+length]
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata = True
    for i in md.disasm(code, BASE+rva):
        r = i.address - BASE
        if lo is not None and not (lo <= r <= hi): continue
        print("%x  %-22s %s %s" % (r, i.bytes.hex(), i.mnemonic, i.op_str))
if __name__ == "__main__":
    a = sys.argv
    rva = int(a[1],0); ln = int(a[2],0)
    lo = int(a[3],0) if len(a) > 3 else None
    hi = int(a[4],0) if len(a) > 4 else None
    dis(rva, ln, lo, hi)
