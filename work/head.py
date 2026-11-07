
import os
DIS=r'C:\PS5contrib\work\disasm'
for n in ('717_4f7250','627_4a2850','724_4f7940','641_4a2de0'):
    print('=====',n)
    lines=open(os.path.join(DIS,n+'.txt')).read().splitlines()
    print('\n'.join(lines[:12]))
    print('  ... total',len(lines))
