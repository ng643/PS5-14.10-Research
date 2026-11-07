
import os
DIS=r'C:\PS5contrib\work\disasm'
def show(num):
    p=[f for f in os.listdir(DIS) if f.startswith('%d_'%num)][0]
    lines=open(os.path.join(DIS,p)).read().splitlines()
    print('===== %d (%d lines) ====='%(num,len(lines)))
    for ln in lines: print(ln)
for n in (612,613): show(n)
