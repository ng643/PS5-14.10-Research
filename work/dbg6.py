
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
for e,n in ((0x34b7b0,86),(0x34c350,191)):
    print("===== func %#x =====" % e)
    ins = K.disasm(e, 0x600)[:n]
    for i in ins:
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
    print()
