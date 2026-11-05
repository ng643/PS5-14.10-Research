
import struct,json
from capstone import *
img=open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
BASE=0xffffffff8a9c0000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
def show(a,b,label):
    print("-- %s --"%label)
    for ins in md.disasm(img[a:b],BASE+a):
        print("  %08x  %-22s %s %s"%(ins.address-BASE,ins.bytes.hex(),ins.mnemonic,ins.op_str))
show(0x55ef30,0x55ef90,"body call site to 0x55f010")
show(0x55e770,0x55e830,"lookup helper 0x55e770 head")
# enclosing function of 0x4ea5ae
print("-- prologues before 0x4ea5ae (nearest 3) --")
c=[]
for i in range(0x4e9000,0x4ea5ae):
    if img[i:i+4]==b"\x55\x48\x89\xe5": c.append(i)
print([hex(x) for x in c[-3:]])
# map bodies to syscalls
idx=json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
bodies={}
for e in idx["entries"]:
    th=int(e["sy_call"],16)-BASE
    rel=struct.unpack_from("<i",img,th+1)[0]
    bodies.setdefault(th+5+rel,[]).append(e["num"])
print("-- syscalls whose body is near 0x4ea5ae --")
for b in sorted(bodies):
    if 0x4e9000<=b<=0x4ea5ae: print("   body 0x%06x sys %s"%(b,bodies[b][:8]))

