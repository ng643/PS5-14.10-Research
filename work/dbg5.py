
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
for e,n in ((0x4f7370,128),(0x34bc60,87)):
    print("===== func %#x =====" % e)
    ins = K.disasm(e, 0x400)[:n]
    for i in ins:
        print("  %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
    print()
