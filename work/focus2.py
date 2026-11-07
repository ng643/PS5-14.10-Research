
import os
DIS=r'C:\PS5contrib\work\disasm'
def load(num):
    p=[f for f in os.listdir(DIS) if f.startswith('%d_'%num)][0]
    ins=[]
    for ln in open(os.path.join(DIS,p)).read().splitlines():
        addr,hx,rest=ln.split(None,2)
        m,_,o=rest.partition(' ')
        ins.append((int(addr,16),m,o.strip(),hx))
    return ins
def interesting(num,before=6,after=2):
    ins=load(num); keep=set()
    for i,(a,m,o,hx) in enumerate(ins):
        if '[rsi' in o or 'gs:' in o or m=='call' or 'copy' in o:
            for k in range(max(0,i-before), min(len(ins),i+after)): keep.add(k)
    res=[]; prev=-2
    for i in sorted(keep):
        if i!=prev+1: res.append('   ...')
        a,m,o,hx=ins[i]; res.append('%08x %-7s %s'%(a,m,o)); prev=i
    return res
for num in (717,724):
    print('########## %d ##########'%num)
    print('\n'.join(interesting(num)))
    print()
