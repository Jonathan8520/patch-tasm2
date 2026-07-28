import struct, sys, bisect
sys.path.insert(0,'/home/user/patch-tasm2/tools')
from st import B,TA,TO,TS,WORDS,dec

LO,HI = int(sys.argv[1],16), int(sys.argv[2],16)
RESET = (len(sys.argv)<4 or sys.argv[3]!='noreset')
funcs = sorted(set(B.func_starts))
CS=set(range(0,19))          # x0..x18 caller-saved

def branch_targets(lo,hi):
    t=set()
    for va in range(lo,hi,4):
        w=WORDS[(va-TA)//4]
        top=(w>>26)&0x3f
        if top==0x05 or top==0x25:
            imm=w&0x3ffffff
            if imm>=1<<25: imm-=1<<26
            t.add(va+imm*4)
        elif (w>>24)&0xff==0x54:
            imm=(w>>5)&0x7ffff
            if imm>=1<<18: imm-=1<<19
            t.add(va+imm*4)
        elif (w>>24)&0x7f in (0x34,0x35):
            imm=(w>>5)&0x7ffff
            if imm>=1<<18: imm-=1<<19
            t.add(va+imm*4)
        elif (w>>24)&0x7f in (0x36,0x37):
            imm=(w>>5)&0x3fff
            if imm>=1<<13: imm-=1<<14
            t.add(va+imm*4)
    return t

hits=[]; regoff=[]
for fi,fs in enumerate(funcs):
    fe = funcs[fi+1] if fi+1<len(funcs) else TA+TS
    if fs<TA or fe>TA+TS or fe<=fs: continue
    bt = branch_targets(fs,fe) if RESET else set()
    st={0:('ARG0',0),1:('ARG1',0),2:('ARG2',0),3:('ARG3',0)}
    for va in range(fs,fe,4):
        if va in bt: st={}
        w=WORDS[(va-TA)//4]
        d=dec(w)
        if d is not None:
            Rn=d['Rn']; base=st.get(Rn) if Rn!=31 else None
            if base is not None:
                if d['off'] is None:
                    regoff.append((va,base,d,fs))
                else:
                    lo=base[1]+d['off']; hi=lo+d['n']
                    if lo<HI and hi>LO:
                        hits.append((va,d['kind'],base[0],base[1],d['off'],d['n'],fs))
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
        if not done and ((w>>24)&0x9f)==0x90:      # ADRP
            imm=(((w>>5)&0x7ffff)<<2)|((w>>29)&3)
            if imm>=(1<<20): imm-=1<<21
            st[Rd]=('#%x'%(((va>>12)<<12)+imm*4096),0); done=True
        if not done and ((w>>22)&0x3ff)==0x3e5:    # LDR Xt,[Xn,#imm]
            Rn=(w>>5)&0x1f; imm=((w>>10)&0xfff)*8
            src=st.get(Rn) if Rn!=31 else None
            if src is not None and src[0].startswith('#'):
                st[Rd]=('MEM[%x]'%(int(src[0][1:],16)+src[1]+imm),0)
            else: st.pop(Rd,None)
            done=True
        if not done and (w>>26)&0x3f==0x25:
            for r in CS: st.pop(r,None)
            done=True
        if not done and (w>>26)&0x3f==0x05: done=True
        if not done and ((w&0xfffffc1f)==0xd63f0000 or (w&0xfffffc1f)==0xd61f0000):
            for r in CS: st.pop(r,None); 
            done=True
        if not done: st.pop(Rd,None)

print("### stores overlapping [0x%x,0x%x)  reset=%s"%(LO,HI,RESET))
for va,kind,sym,disp,off,n,fs in hits:
    print("0x%x %-9s base=%s+0x%x off=0x%x n=%d func=0x%x"%(va,kind,sym,disp,off,n,fs))
print("total",len(hits))
print("### regoff stores, base tracked")
for va,base,d,fs in regoff:
    print("0x%x base=%s+0x%x n=%d func=0x%x"%(va,base[0],base[1],d['n'],fs))
print("total",len(regoff))
