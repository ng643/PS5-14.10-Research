
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
def show(lo, hi, label=""):
    print("---- %s %#x..%#x" % (label, lo, hi))
    for i in K.disasm(lo, hi-lo):
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
show(0x3afa40, 0x3afb00, "662 [rbx+8] and len setup")
