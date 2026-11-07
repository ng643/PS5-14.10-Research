
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
for base in (0xE61430,):
    print('table @%x' % base)
    for i in range(8):
        off=base+i*24
        vals=[int.from_bytes(IMG[off+k*8:off+k*8+8],'little') for k in range(3)]
        print('  idx %d: %s' % (i, [hex(v) for v in vals]))
