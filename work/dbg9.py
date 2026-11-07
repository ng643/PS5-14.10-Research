
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K

def show(lo, hi, label=""):
    print("---- %s %#x..%#x" % (label, lo, hi))
    ins = K.disasm(lo, hi-lo)
    for i in ins:
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))

show(0x3af920, 0x3af9c0, "662 body entry")
print()
show(0x3b0120, 0x3b01b0, "662 copyout site")
