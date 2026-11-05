import struct
BASE = 0xffffffff8a9c0000
img = open(r"C:\\PS5contrib\\docs\\dumps_13.60\\kernel_text.bin","rb").read()
N = len(img)
def q(off):
    if off < 0 or off+8 > N: return None
    return struct.unpack_from("<Q", img, off)[0]
def rva(va):
    return None if va is None else va - BASE

known = {585: 0x8FC610, 628: 0x3CB450, 601: 0xCA0D6C, 629: 0x91BCA0, 566: 0x350CD0}
target = BASE + known[585]
pat = struct.pack("<Q", target)
hits = []
i = img.find(pat)
while i >= 0:
    hits.append(i); i = img.find(pat, i+1)
print("occurrences of 585 body ptr:", len(hits), [hex(h) for h in hits[:10]])

for stride in (24, 32, 40):
    for h in hits:
        base = h - 585*stride
        if base < 0: continue
        ok = 0
        for num, r in known.items():
            v = q(base + num*stride)
            if v == BASE + r: ok += 1
        if ok >= 2:
            print("TABLE base=%016X stride=%d matched=%d" % (BASE+base, stride, ok))
            for num in sorted(known):
                v = q(base + num*stride)
                print("   sys %d -> %s" % (num, hex(v) if v else "?"))
            for num in (674, 673, 675, 676, 677):
                v = q(base + num*stride)
                print("   sys %d -> %s  (rva %s)" % (num, hex(v) if v else "?", hex(v-BASE) if v and BASE <= v < BASE+N else "-"))
