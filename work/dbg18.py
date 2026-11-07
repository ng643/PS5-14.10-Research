
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
def show(lo, hi, label=""):
    print("---- %s %#x..%#x" % (label, lo, hi))
    for i in K.disasm(lo, hi-lo):
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
show(0x34bf80, 0x34c060, "0x34c009 ctx")
show(0x446120, 0x4461b0, "0x446177 ctx")
