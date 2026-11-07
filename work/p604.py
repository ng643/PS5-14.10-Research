
import os
DIS=r'C:\PS5contrib\work\disasm'
def show(num,start=0,end=10**9):
    p=[f for f in os.listdir(DIS) if f.startswith('%d_'%num)][0]
    lines=open(os.path.join(DIS,p)).read().splitlines()
    print('===== %d (%d lines) ====='%(num,len(lines)))
    for ln in lines[start:end]: print(ln)
show(604)
