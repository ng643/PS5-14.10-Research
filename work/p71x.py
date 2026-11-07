
import os
DIS=r'C:\PS5contrib\work\disasm'
for n in ('717_4f7250','724_4f7940'):
    print('=====',n)
    print(open(os.path.join(DIS,n+'.txt')).read())
