import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE = 0xffffffff8a9c0000
img = open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
def rd(off, n): return img[off:off+n]
def i32(off): return struct.unpack_from("<i", img, off)[0]
def u32(off): return struct.unpack_from("<I", img, off)[0]
def u64(off): return struct.unpack_from("<Q", img, off)[0]

def follow(rva):
    for _ in range(4):
        b = rd(rva, 5)
        if b[0] == 0xe9:
            rva = rva + 5 + i32(rva+1)
        elif b[0] == 0x48 and b[1] == 0xe9:
            rva = rva + 6 + i32(rva+2)
        else:
            break
    return rva

t = 0x265fa0
print("thunk", hex(t), rd(t,8).hex())
body = follow(t)
print("body", hex(body))
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = rd(body, 900)
for ins in md.disasm(code, BASE+body):
    print("%08X  %-8s %s" % (ins.address - BASE, ins.mnemonic, ins.op_str))
    if ins.mnemonic == "ret": break
