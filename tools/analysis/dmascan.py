"""Find prebuilt display-list packets in the image by their full signature.

An earlier attempt scanned for bare GIF tags and produced 2,859 hits, almost
all of them MIPS instructions that happen to have the right bit pattern -- a
control run on random bytes showed the filter was measuring structure, not
GIF tags. The fix is to require the whole wrapper the game actually emits,
learned from running SetGSReg:

    +0  DMAtag   qwc, id in {cnt, ref, refe, next, end}
    +8  VIFcode  FLUSH / NOP / STCYCL ...
    +c  VIFcode  DIRECT with num == qwc
    +10 GIFtag   consistent nloop/nreg/format

Four independent fields all agreeing is a far narrower target than one, and
the same control experiment is run here so the false-positive rate is
measured rather than assumed.

usage: python dmascan.py <SCUS_972.05>
"""
import os, struct, sys
import gs

OK_ID = {0, 1, 2, 3, 7}          # refe, cnt, next, ref, end
VIF_OK = {0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x10, 0x11, 0x13, 0x14, 0x17}


def hit(blob, off):
    """Does a full DMA+VIF+GIF wrapper start at off?"""
    if off + 32 > len(blob):
        return None
    dma, addr, v0, v1 = struct.unpack_from('<IIII', blob, off)
    qwc, did = dma & 0xffff, (dma >> 28) & 7
    if did not in OK_ID or not (0 < qwc <= 0x3ff):
        return None
    if (dma >> 16) & 0x0fff:                 # reserved bits must be clear
        return None
    if (v0 >> 24) not in VIF_OK or (v0 & 0x00ffffff) and (v0 >> 24) != 0x01:
        return None
    if (v1 >> 24) not in (0x50, 0x51):       # DIRECT / DIRECTHL
        return None
    if (v1 & 0xffff) != qwc:                 # the sizes must agree
        return None
    lo, hi = struct.unpack_from('<QQ', blob, off + 16)
    t = gs.GifTag(lo, hi)
    if not t.plausible() or t.nloop > qwc * 16:
        return None
    return qwc, did, t


def scan(blob):
    out = []
    for off in range(0, len(blob) - 32, 4):     # tags are quadword-aligned in
        h = hit(blob, off)                      # practice, but do not assume
        if h:
            out.append((off, h))
    return out


def selfcheck():
    """The filter must accept a packet the ROM really built.

    A detector that finds nothing is indistinguishable from a broken one, and
    this scan's answer is 'nothing', so the known positive matters more than
    usual. These are the exact bytes SetGSReg wrote, captured by running it
    in the interpreter (see gs_rom_test.py).
    """
    pkt = struct.pack('<IIII', 0x10000002, 0, 0x11000000, 0x50000002)
    pkt += struct.pack('<QQ', 0x1000000000008001, 0xe)
    pkt += struct.pack('<QQ', 0x1, 0x47)
    h = hit(pkt, 0)
    assert h and h[0] == 2 and h[1] == 1, h
    assert h[2].nloop == 1 and h[2].nreg == 1 and h[2].regs == [0xe]
    # and reject the same bytes with the DIRECT size disagreeing
    bad = bytearray(pkt); bad[12:16] = struct.pack('<I', 0x50000009)
    assert hit(bytes(bad), 0) is None
    print('selfcheck ok')


if __name__ == '__main__':
    selfcheck()
    if len(sys.argv) < 2:
        raise SystemExit(__doc__.strip().splitlines()[-1])
    elf = sys.argv[1]
    from disasm import Image
    img = Image(elf)
    blob = img.d[img.off:img.off + img.size]
    hits = scan(blob)

    # Control: the same filter over the same volume of random bytes. If the
    # rates are close, the filter is finding structure, not packets.
    ctl = scan(os.urandom(len(blob)))
    per_mb = lambda n: n / (len(blob) / 1e6)
    print(f'image  {len(blob):,} bytes -> {len(hits)} hits '
          f'({per_mb(len(hits)):.2f}/MB)')
    print(f'random {len(blob):,} bytes -> {len(ctl)} hits '
          f'({per_mb(len(ctl)):.2f}/MB)')
    if len(ctl) and len(hits) / max(len(ctl), 1) < 5:
        print('\nnot a usable signal: the control rate is too close.')
        raise SystemExit(0)
    print(f'\nsignal is {len(hits) / max(len(ctl), 1):.0f}x the control rate\n')
    for off, (qwc, did, t) in hits[:20]:
        print(f'0x{img.base + off:08x}  qwc={qwc:3d} '
              f'{ {0:"refe",1:"cnt",2:"next",3:"ref",7:"end"}[did]:4s}  '
              f'{t.describe().splitlines()[0]}')
        for line in gs.decode(blob[off + 16:off + 16 + qwc * 16], limit=3)[1:6]:
            print('      ' + line.strip())
