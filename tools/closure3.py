import sys,bisect; sys.path.insert(0,'/home/user/patch-tasm2/tools')
from st import B,TA,TS,WORDS,dec
funcs=sorted(set(B.func_starts))
CS=set(range(0,19))
def frange(va):
    i=bisect.bisect_right(funcs,va)-1
    return funcs[i],(funcs[i+1] if i+1<len(funcs) else TA+TS)

def wb(w):
    """return (Rn, delta) if this ld/st (load OR store) writes back to its base, else None"""
    hi=(w>>27)&0x7
    if hi==0x7 and ((w>>24)&3)==0 and ((w>>21)&1)==0:
        k=(w>>10)&3
        if k in (1,3):
            imm=(w>>12)&0x1ff
            if imm>=0x100: imm-=0x200
            return ((w>>5)&0x1f, imm)
        return None
    if hi==0x5 and ((w>>25)&1)==0:
        cls=(w>>23)&3
        if cls in (1,3):
            o=(w>>30)&3; V=(w>>26)&1
            es = ({0:4,1:8,2:16}.get(o) if V else ({0:4,2:8}.get(o)))
            if es is None: return None
            imm=(w>>15)&0x7f
            if imm>=0x40: imm-=0x80
            return ((w>>5)&0x1f, imm*es)
    return None

def run(fs,fe,seed,GLOB=False):
    st=dict(seed); calls=[]; stores=[]; aliases=[]
    for va in range(fs,fe,4):
        w=WORDS[(va-TA)//4]
        d=dec(w)
        if d is not None:
            Rn=d['Rn']; base=st.get(Rn) if Rn!=31 else None
            if base is not None: stores.append((va,base,d))
            for k in ('Rt','Rt2'):
                if k in d and d[k]!=31:
                    v=st.get(d[k])
                    if v is not None: aliases.append((va,v,base,d))
        u=wb(w)
        if u:
            Rn,delta=u; src=st.get(Rn)
            if src is not None: st[Rn]=(src[0],src[1]+delta)
            else: st.pop(Rn,None)
            if d is not None: continue
        elif d is not None:
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
        if not done and GLOB and ((w>>24)&0x9f)==0x90:
            imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3)
            if imm>=(1<<20): imm-=1<<21
            st[Rd]=('#%x'%(((va>>12)<<12)+imm*4096),0); done=True
        if not done and GLOB and ((w>>22)&0x3ff)==0x3e5:
            Rn=(w>>5)&0x1f; imm=((w>>10)&0xfff)*8
            src=st.get(Rn) if Rn!=31 else None
            if src is not None and src[0].startswith('#'):
                st[Rd]=('MEM[%x]'%(int(src[0][1:],16)+src[1]+imm),0)
            else: st.pop(Rd,None)
            done=True
        if not done and (w>>26)&0x3f in (0x25,0x05):
            imm=w&0x3ffffff
            if imm>=1<<25: imm-=1<<26
            tgt=va+imm*4; isbl=((w>>26)&0x3f)==0x25
            if isbl or not (fs<=tgt<fe):
                args={i:st.get(i) for i in range(8) if st.get(i) is not None}
                if args: calls.append((va,tgt,args))
            if isbl:
                for r in CS: st.pop(r,None)
            done=True
        if not done and ((w&0xfffffc1f)==0xd63f0000 or (w&0xfffffc1f)==0xd61f0000):
            args={i:st.get(i) for i in range(8) if st.get(i) is not None}
            calls.append((va,None,args))
            for r in CS: st.pop(r,None)
            done=True
        if not done: st.pop(Rd,None)
    return calls,stores,aliases
