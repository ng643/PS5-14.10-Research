
import json, re, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=0xffffffff8a9c0000
img=open("docs/dumps_13.60/kernel_text.bin","rb").read()
rows=json.load(open(".local/allcopy_sites.json"))
se=json.load(open("docs/dumps_13.60/sysent_index.json"))
if isinstance(se,dict):
    for k in ("entries","sysents","syscalls","rows"):
        if k in se: se=se[k]; break
bodies=sorted({int(e["sy_call_off"],16) for e in se if e.get("sy_call_off")})
md=Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata=True
def body_of(rva):
    i=bisect.bisect_right(bodies,rva)-1
    return bodies[i] if i>=0 else rva
out=[]
mem=[r for r in rows if r.get("len_kind")=="mem"]
for r in mem:
    rva=r["rva"]; s=(r.get("len_set") or "").strip()
    m=re.search(r"\[rbp - (0x[0-9a-f]+)\]", s)
    if not m:
        out.append((rva,r["call"],s,"reg-relative","")); continue
    disp=int(m.group(1),16)
    start=max(body_of(rva), rva-0x1800)
    want=("qwordptr[rbp-"+hex(disp)+"]","dwordptr[rbp-"+hex(disp)+"]","byteptr[rbp-"+hex(disp)+"]","wordptr[rbp-"+hex(disp)+"]")
    lastw=""; n=0
    for ins in md.disasm(img[start:rva], BASE+start):
        n+=1
        if n>6000: break
        parts=[p.strip().replace(" ","") for p in ins.op_str.split(",")]
        if parts and parts[0] in want:
            lastw="0x%x %s %s"%(ins.address-BASE,ins.mnemonic,ins.op_str)
    out.append((rva,r["call"],s,"slot",lastw or "NONE(scan %d..%x)"%(start,rva)))
lines=[]
for o in out:
    lines.append("%-9s %-7s %-28s %s"%(hex(o[0]),o[1],o[2][:28],o[4]))
open(".local/memslot_report.txt","w").write("\n".join(lines))
print("\n".join(lines[:20]))
print("... total",len(lines),"-> .local/memslot_report.txt")
