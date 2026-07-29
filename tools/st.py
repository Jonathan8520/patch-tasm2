import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from machoscan import Bin
B = Bin(os.environ.get("TASM2_BIN", "/home/user/AmazingSpiderMan2"))
TA, TO, TS = B.sections['__text']
WORDS = struct.unpack('<%dI'%(TS//4), B.data[TO:TO+TS])

def dec(w):
    """-> dict or None.  kind: imm|unscaled|post|pre|regoff|pair|pairpost|pairpre|
       simdstruct|excl|atomic ; keys: Rn, off (bytes, None if reg), n (bytes written), Rt,Rt2"""
    size=(w>>30)&3; V=(w>>26)&1; opc=(w>>22)&3; Rn=(w>>5)&0x1f; Rt=w&0x1f
    hi=(w>>27)&0x7
    if hi==0x7 and ((w>>24)&3)==1:            # unsigned imm
        if V==0:
            if opc!=0: return None
            n=1<<size; sc=size
        else:
            if opc==0: n=1<<size; sc=size
            elif opc==2 and size==0: n=16; sc=4
            else: return None
        imm=(w>>10)&0xfff
        return dict(kind='imm',Rn=Rn,off=imm<<sc,n=n,Rt=Rt)
    if hi==0x7 and ((w>>24)&3)==0:
        b21=(w>>21)&1; b1110=(w>>10)&3
        if V==0:
            store = (opc==0)
            n=1<<size
        else:
            store = (opc==0) or (opc==2 and size==0)
            n=(1<<size) if opc==0 else 16
        if b21==0:
            imm=(w>>12)&0x1ff
            if imm>=0x100: imm-=0x200
            if not store: return None
            k={0:'unscaled',1:'post',3:'pre',2:'unpriv'}[b1110]
            return dict(kind=k,Rn=Rn,off=(0 if k=='post' else imm),n=n,Rt=Rt,imm=imm)
        else:
            if b1110==2:
                if not store: return None
                return dict(kind='regoff',Rn=Rn,off=None,n=n,Rt=Rt,Rm=(w>>16)&0x1f)
            if b1110==0 and V==0:
                return dict(kind='atomic',Rn=Rn,off=0,n=1<<size,Rt=Rt)
            return None
    if hi==0x5 and ((w>>25)&1)==0:             # pair (bit25 must be 0)
        L=(w>>22)&1; cls=(w>>23)&3
        if L: return None
        o=(w>>30)&3
        if V==0:
            if o==0: es=4
            elif o==2: es=8
            else: return None
        else:
            es={0:4,1:8,2:16}.get(o)
            if es is None: return None
        imm=(w>>15)&0x7f
        if imm>=0x40: imm-=0x80
        k={0:'pairnt',1:'pairpost',2:'pair',3:'pairpre'}[cls]
        off = 0 if k=='pairpost' else imm*es
        return dict(kind=k,Rn=Rn,off=off,n=es*2,Rt=Rt,Rt2=(w>>10)&0x1f,imm=imm*es)
    if (w>>24)&0xbf in (0x0c,0x0d):             # ASIMD ld/st struct (bit31=0)
        if ((w>>22)&1)==0 and ((w>>31)&1)==0:
            return dict(kind='simdstruct',Rn=Rn,off=0,n=64,Rt=Rt)
        return None
    if ((w>>24)&0x3f)==0x08:                    # exclusive / release
        if ((w>>22)&1)==0:
            return dict(kind='excl',Rn=Rn,off=0,n=1<<size,Rt=Rt)
        return None
    return None
