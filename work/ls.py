
import os
DIS=r'C:\PS5contrib\work\disasm'
for f in sorted(os.listdir(DIS)):
    print(f, os.path.getsize(os.path.join(DIS,f)))
