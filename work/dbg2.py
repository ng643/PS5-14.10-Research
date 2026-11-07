
import sys, json
sys.path.insert(0, r"C:\PS5contrib\work")
import kptr_reach as K

sites = {0x4f757f:("rax+0x88",[536,604]), 0x34b8e2:("r14+0x10",[593,659]),
         0xca1b8b:("r13+0x578",[601]), 0x34c647:("r14+0x10",[656]),
         0x34bd8e:("r14+0x10",[660]), 0x3b018a:("rbx+8",[661,662,668]),
         0x3b1612:("rbx+0x10",[661,662,663,664,668]), 0x3b1f6d:("rbx+0x18",[665,666])}
for n in (536,604,593,659,601,656,660,661,662,663,664,665,666,668):
    e = K.syent[n]; t = K.thunk_target(e["sy_call_off"])
    print("sys %3d narg=%s thunk=%s handler=%s est=%#x" % (n, e["narg"], e["sy_call_off"], hex(t) if t else None, K.estimate_size(t) if t else 0))
print()
for s, (src, nums) in sites.items():
    print("== site %#x src [%s] sys %s" % (s, src, nums))
