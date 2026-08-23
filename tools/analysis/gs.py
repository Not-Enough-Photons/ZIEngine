"""Decode GS packets: GIF tags and the register writes they carry.

The PS2 has no draw calls. The game builds DMA chains of GIF packets and the
Graphics Synthesizer consumes them, so "what does the renderer do" is really
"what register writes does it emit". This turns a blob of quadwords into a
readable list of primitives and state changes.

Written from the documented GS/GIF register layout. Independent of the
interpreter and the lifter -- it reads bytes, nothing else.

usage: python gs.py <SCUS_972.05> [--scan | 0xADDR [count]]
"""
import struct, sys

# GIF tag data formats
PACKED, REGLIST, IMAGE, DISABLE = 0, 1, 2, 3
FMT = {PACKED: 'PACKED', REGLIST: 'REGLIST', IMAGE: 'IMAGE', DISABLE: 'DISABLE'}

# The register descriptors a GIF tag can name (the low nibble of each REGS slot)
REGS = {
    0x0: 'PRIM', 0x1: 'RGBAQ', 0x2: 'ST', 0x3: 'UV', 0x4: 'XYZF2', 0x5: 'XYZ2',
    0x6: 'TEX0_1', 0x7: 'TEX0_2', 0x8: 'CLAMP_1', 0x9: 'CLAMP_2', 0xa: 'FOG',
    0xc: 'XYZF3', 0xd: 'XYZ3', 0xe: 'A+D', 0xf: 'NOP',
}

# Registers reachable through the A+D (address+data) descriptor
AD = {
    0x00: 'PRIM', 0x01: 'RGBAQ', 0x02: 'ST', 0x03: 'UV', 0x04: 'XYZF2',
    0x05: 'XYZ2', 0x06: 'TEX0_1', 0x07: 'TEX0_2', 0x08: 'CLAMP_1',
    0x09: 'CLAMP_2', 0x0a: 'FOG', 0x0c: 'XYZF3', 0x0d: 'XYZ3',
    0x14: 'TEX1_1', 0x15: 'TEX1_2', 0x16: 'TEX2_1', 0x17: 'TEX2_2',
    0x18: 'XYOFFSET_1', 0x19: 'XYOFFSET_2', 0x1a: 'PRMODECONT',
    0x1b: 'PRMODE', 0x1c: 'TEXCLUT', 0x22: 'SCANMSK', 0x34: 'MIPTBP1_1',
    0x35: 'MIPTBP1_2', 0x36: 'MIPTBP2_1', 0x37: 'MIPTBP2_2',
    0x3b: 'TEXA', 0x3d: 'FOGCOL', 0x3f: 'TEXFLUSH',
    0x40: 'SCISSOR_1', 0x41: 'SCISSOR_2', 0x42: 'ALPHA_1', 0x43: 'ALPHA_2',
    0x44: 'DIMX', 0x45: 'DTHE', 0x46: 'COLCLAMP', 0x47: 'TEST_1',
    0x48: 'TEST_2', 0x49: 'PABE', 0x4a: 'FBA_1', 0x4b: 'FBA_2',
    0x4c: 'FRAME_1', 0x4d: 'FRAME_2', 0x4e: 'ZBUF_1', 0x4f: 'ZBUF_2',
    0x50: 'BITBLTBUF', 0x51: 'TRXPOS', 0x52: 'TRXREG', 0x53: 'TRXDIR',
    0x54: 'HWREG', 0x60: 'SIGNAL', 0x61: 'FINISH', 0x62: 'LABEL',
}

PRIM_TYPE = ['POINT', 'LINE', 'LINE_STRIP', 'TRI', 'TRI_STRIP', 'TRI_FAN',
             'SPRITE', 'INVALID']


class GifTag:
    __slots__ = ('nloop', 'eop', 'pre', 'prim', 'flg', 'nreg', 'regs')

    def __init__(self, lo, hi):
        self.nloop = lo & 0x7fff
        self.eop = (lo >> 15) & 1
        self.pre = (lo >> 46) & 1
        self.prim = (lo >> 47) & 0x7ff
        self.flg = (lo >> 58) & 3
        n = (lo >> 60) & 0xf
        self.nreg = n if n else 16
        self.regs = [(hi >> (4 * i)) & 0xf for i in range(self.nreg)]

    def plausible(self):
        """Cheap sanity filter for scanning raw memory."""
        if self.flg == DISABLE or self.nloop == 0:
            return False
        if self.flg in (PACKED, REGLIST) and any(
                r not in REGS for r in self.regs):
            return False
        return self.nloop < 0x4000

    def describe(self):
        s = (f'GIFtag nloop={self.nloop} eop={self.eop} '
             f'fmt={FMT[self.flg]} nreg={self.nreg}')
        if self.pre:
            s += f'  PRIM={prim_str(self.prim)}'
        if self.flg in (PACKED, REGLIST):
            s += '\n         regs: ' + ' '.join(
                REGS.get(r, f'?{r:x}') for r in self.regs)
        return s


def prim_str(p):
    out = [PRIM_TYPE[p & 7]]
    if (p >> 3) & 1: out.append('gouraud')
    if (p >> 4) & 1: out.append('textured')
    if (p >> 5) & 1: out.append('fog')
    if (p >> 6) & 1: out.append('alpha')
    if (p >> 7) & 1: out.append('aa1')
    out.append('UV' if (p >> 8) & 1 else 'STQ')
    if (p >> 9) & 1: out.append('ctxt2')
    if (p >> 10) & 1: out.append('fix')
    return ','.join(out)


def qwords(blob, off=0):
    while off + 16 <= len(blob):
        lo, hi = struct.unpack_from('<QQ', blob, off)
        yield off, lo, hi
        off += 16


def decode(blob, limit=40):
    """Walk a packet, yielding human-readable lines."""
    out, off, n = [], 0, 0
    while off + 16 <= len(blob) and n < limit:
        lo, hi = struct.unpack_from('<QQ', blob, off)
        t = GifTag(lo, hi)
        if not t.plausible():
            out.append(f'{off:06x}  (not a GIF tag: {lo:016x} {hi:016x})')
            break
        out.append(f'{off:06x}  {t.describe()}')
        off += 16
        n += 1
        if t.flg == IMAGE:
            out.append(f'        <{t.nloop} qwords of image data>')
            off += t.nloop * 16
            if t.eop:
                break
            continue
        for _ in range(t.nloop):
            for r in t.regs:
                if off + 16 > len(blob):
                    return out
                d0, d1 = struct.unpack_from('<QQ', blob, off)
                off += 16
                if r == 0xe:                       # A+D: register in the hi word
                    reg = d1 & 0xff
                    out.append(f'        A+D {AD.get(reg, hex(reg)):12s}'
                               f' = {d0:016x}')
                elif r == 0xf:
                    pass                           # NOP
                else:
                    out.append(f'        {REGS.get(r, "?"):12s}   {d0:016x}')
        if t.eop:
            break
    return out


def scan(path, minhits=3):
    """Find static GIF packets sitting in the ROM's data."""
    from disasm import Image
    img = Image(path)
    blob = img.d[img.off:img.off + img.size]
    hits = []
    for off in range(0, len(blob) - 16, 16):
        lo, hi = struct.unpack_from('<QQ', blob, off)
        t = GifTag(lo, hi)
        if not t.plausible() or t.nloop > 64:
            continue
        # require a recognisable primitive or a run of real A+D writes
        if t.pre and (t.prim & 7) < 7:
            hits.append((img.base + off, t))
        elif t.flg == PACKED and all(r in (0xe, 0xf) for r in t.regs):
            hits.append((img.base + off, t))
    return img, blob, hits


def demo():
    # A PACKED tag: 1 loop, EOP, PRE set, TRI_STRIP + gouraud + textured,
    # 3 registers (RGBAQ, ST, XYZF2)
    prim = 4 | (1 << 3) | (1 << 4)
    lo = 1 | (1 << 15) | (1 << 46) | (prim << 47) | (PACKED << 58) | (3 << 60)
    hi = 0x1 | (0x2 << 4) | (0x4 << 8)
    t = GifTag(lo, hi)
    assert t.nloop == 1 and t.eop == 1 and t.pre == 1
    assert t.nreg == 3 and t.regs == [1, 2, 4]
    assert t.flg == PACKED
    assert 'TRI_STRIP' in prim_str(t.prim) and 'textured' in prim_str(t.prim)
    assert [REGS[r] for r in t.regs] == ['RGBAQ', 'ST', 'XYZF2']
    # nreg == 0 encodes 16, not zero
    t2 = GifTag(1 | (0 << 60), 0)
    assert t2.nreg == 16
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        demo()
    elif sys.argv[1].endswith('.05') and len(sys.argv) > 2 and sys.argv[2] == '--scan':
        img, blob, hits = scan(sys.argv[1])
        print(f'static GIF packets found in the image: {len(hits)}')
        for a, t in hits[:12]:
            print(f'  0x{a:08x}  {t.describe()}')
    else:
        from disasm import Image
        img = Image(sys.argv[1])
        addr = int(sys.argv[2], 16)
        cnt = int(sys.argv[3]) if len(sys.argv) > 3 else 16
        print('\n'.join(decode(img.read(addr, cnt * 16))))
