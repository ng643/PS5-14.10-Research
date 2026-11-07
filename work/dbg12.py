
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
def show(lo, hi, label=""):
    print("---- %s %#x..%#x" % (label, lo, hi))
    for i in K.disasm(lo, hi-lo):
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
show(0x3b15a0, 0x3b1630, "664 site 0x3b1612")
show(0x3b1f00, 0x3b1f90, "666 site 0x3b1f6d")
