
import os,re,glob
HELP={'8ac191d0':'copyout','8ac19280':'copyin','8ac190b0':'memcpy','8ac19900':'copyinstr','8ac19720':'suword64','8ac19790':'suword32','8b782520':'uiomove','8ac19520':'?copyout2'}
d=r'C:\PS5contrib\work\disasm'
for f in sorted(glob.glob(d+r'\*.txt')):
    lines=open(f,encoding='utf-8',errors='replace').read().splitlines()
    ins=[]
    for ln in lines:
        p=ln.split(None,2)
        if len(p)>=3 and re.fullmatch(r'[0-9a-f]{8}',p[0]):
            ins.append((p[0],p[2]))
        elif len(p)==2 and re.fullmatch(r'[0-9a-f]{8}',p[0]):
            ins.append((p[0],p[1]))
    print('\n=== %s  (%d ins) ==='%(os.path.basename(f),len(ins)))
    for i,(a,t) in enumerate(ins):
        m=re.search(r'call\s+0x([0-9a-f]{16})',t)
        if m:
            tgt=m.group(1)[-8:]
            if tgt in HELP:
                for j in range(max(0,i-4),min(len(ins),i+3)):
                    mark='>>' if j==i else '  '
                    print('%s %s %s'%(mark,ins[j][0],ins[j][1]))
                print('   --')
