
D=r'C:\PS5contrib\docs\dumps_13.60'
IMG=open(D+r'\kernel_text.bin','rb').read()
import re
print('last lines of 727 file:')
lines=open(r'C:\PS5contrib\work\disasm\727_3b3090.txt').read().splitlines()
print(lines[-1]); print(lines[0])
# find prologue before 0x3b733e
a=0x3b733e
while a>0x3b6000:
    if IMG[a:a+4]==b'\x55\x48\x89\xe5':
        print('prologue at %x (distance %x)'%(a,0x3b733e-a)); break
    a-=1
