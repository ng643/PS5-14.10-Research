
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
for e in (0x3af8e0,0x3af8f0,0x3af900,0x3b01f0,0x3b0fb0,0x3b1670,0x3b1680,0x34b790):
    ins = K.disasm(e, 0x40)
    print("== entry %#x" % e)
    for i in ins:
        print("   %#08x %-18s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
        if i.mnemonic in ("ret","jmp","int3"): break
    print()
