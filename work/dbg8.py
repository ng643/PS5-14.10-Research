
import sys, re
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K

# 601: find stores to [r13+0x578] and the object origin
ins = K.disasm(0xca0630, 0x1ce0)
print("601 insns", len(ins))
for i in ins:
    if "0x578" in i.op_str or "0x580" in i.op_str:
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
print()
print("---- 601 entry")
for i in K.disasm(0xca0630, 0x120):
    print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
