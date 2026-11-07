
import os,re,glob
d=r'C:\PS5contrib\work\disasm'
order=['646','647','642','618','624','733','734','727','728','671','675','705','721','611','612','613','615','604','607','608','641','667','717','724','627','308']
for num in order:
    fs=[f for f in glob.glob(d+r'\*.txt') if os.path.basename(f).startswith(num+'_')]
    if not fs: continue
    f=fs[0]
    ins=[]
    for ln in open(f,encoding='utf-8',errors='replace'):
        p=ln.split(None,2)
        if len(p)>=2 and re.fullmatch(r'[0-9a-f]{8}',p[0]): ins.append((p[0],p[2] if len(p)>2 else p[1]))
    print('\n### %s  (%d ins)'%(os.path.basename(f),len(ins)))
    print('  head:', ' | '.join('%s %s'%(a,t) for a,t in ins[:10]))
    hits=[(a,t) for a,t in ins if re.search(r'\[rsi',t)]
    for a,t in hits[:14]: print('   UAP %s %s'%(a,t))
