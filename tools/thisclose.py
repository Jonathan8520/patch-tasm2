import sys; sys.path.insert(0,'/home/user/patch-tasm2/tools')
from st import B,TA,TS,WORDS,dec
import bisect
funcs=sorted(set(B.func_starts))
CS=set(range(0,19))
def frange(va):
    i=bisect.bisect_right(funcs,va)-1
    return funcs[i], (funcs[i+1] if i+1<len(funcs) else TA+TS)

def scan(fs,fe,seed):
    """seed: dict reg->('THIS',0). returns (calls_with_this, stores_to_this)"""
    st=dict(seed); calls=[]; stores=[]
    for va in range(fs,fe,4):
        w=WORDS[(va-TA)//4]
        d=dec(w)
        if d is not None:
            Rn=d['Rn']; base=st.get(Rn) if Rn!=31 else None
            if base is not None:
                stores.append((va,base[1],d))
            if d['kind'] in ('pre','post','pairpre','pairpost'):
                if base is not None: st[Rn]=(base[0],base[1]+d.get('imm',0))
                else: st.pop(Rn,None)
            continue
        Rd=w&0x1f; done=False
        if (w>>23)&0x1ff in (0x122,0x1a2):
            sf=(w>>31)&1;S=(w>>29)&1;sub=(w>>30)&1;sh=(w>>22)&1;imm=(w>>10)&0xfff;Rn=(w>>5)&0x1f
            if sh: imm<<=12
            if S==0 and sf==1:
                src=st.get(Rn) if Rn!=31 else None
                if src is not None: st[Rd]=(src[0],src[1]+(-imm if sub else imm))
                else: st.pop(Rd,None)
                done=True
        if not done and (w & 0x7fe0ffe0)==0x2a0003e0:
            Rm=(w>>16)&0x1f; src=st.get(Rm)
            if src is not None: st[Rd]=src
            else: st.pop(Rd,None)
            done=True
        if not done and (w>>26)&0x3f==0x25:      # BL
            a0=st.get(0)
            imm=w&0x3ffffff
            if imm>=1<<25: imm-=1<<26
            if a0 is not None: calls.append((va,va+imm*4,a0[1]))
            for r in CS: st.pop(r,None)
            done=True
        if not done and (w>>26)&0x3f==0x05:      # B (tail call)
            a0=st.get(0)
            imm=w&0x3ffffff
            if imm>=1<<25: imm-=1<<26
            tgt=va+imm*4
            if a0 is not None and not (fs<=tgt<fe): calls.append((va,tgt,a0[1]))
            done=True
        if not done and ((w&0xfffffc1f)==0xd63f0000 or (w&0xfffffc1f)==0xd61f0000):
            for r in CS: st.pop(r,None)
            done=True
        if not done: st.pop(Rd,None)
    return calls,stores
