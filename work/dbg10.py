
import sys
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K

def stores(fn, size, pat):
    print("== stores matching %r in %#x" % (pat, fn))
    for i in K.disasm(fn, size):
        if i.mnemonic.startswith("mov") and pat in i.op_str and i.op_str.startswith("qword ptr"):
            print("   %#08x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))

stores(0x3af920, 0x7f0, "[rbx + 8]")
stores(0x3af920, 0x7f0, "[rbx + 0x58]")
stores(0x3af920, 0x7f0, "[rbx + 0x50]")
print()
print("---- 662 body: search for the id lookup / list walk")
for i in K.disasm(0x3af920, 0x7f0):
    if i.mnemonic == "call":
        print("   %#08x call %#x" % (i.address-K.BASE, (i.operands[0].imm & 0xffffffffffffffff)-K.BASE))
