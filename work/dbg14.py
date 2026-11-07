
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
def show(lo, hi, label=""):
    print("---- %s %#x..%#x" % (label, lo, hi))
    for i in K.disasm(lo, hi-lo):
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
show(0xca1d30, 0xca1db0, "601 store +0x578 (A)")
show(0xca0e20, 0xca0e90, "601 store +0x578 (B)")
