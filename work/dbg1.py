
import sys, json
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K
print("593 entry", K.thunk_target(K.syent[593]["sy_call_off"]), "size", K.estimate_size(K.thunk_target(K.syent[593]["sy_call_off"])))
ins = K.disasm(K.thunk_target(K.syent[593]["sy_call_off"]), 64)
for i in ins[:12]:
    print("  %#x %-20s %s %s" % (i.address-K.BASE, i.bytes.hex(), i.mnemonic, i.op_str))
# count all call targets in that handler
e = K.thunk_target(K.syent[593]["sy_call_off"]); sz = K.estimate_size(e)
insns = K.disasm(e, sz)
print("insns", len(insns))
calls = [(i.address-K.BASE, i.operands[0].imm) for i in insns if i.mnemonic=="call" and i.operands and i.operands[0].type==K.CS_OP_IMM]
print("calls", len(calls), calls[:10])
print("targets rva", [hex(t-K.BASE) for a,t in calls[:10]])
