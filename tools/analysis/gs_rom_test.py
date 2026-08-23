"""Capture a GS packet the way the ROM actually builds one, then decode it.

gs.py was written from the documented GIF/GS layout, which makes it a guess
until something from the game agrees with it. This runs SetGSReg -- the
smallest complete packet builder in the image -- in the interpreter, records
every store it makes, and hands the resulting bytes to gs.py.

Agreement here is worth more than a self-check: the packet is built by
Zipper's own code executing R5900 instructions, and the decoder never saw it.

usage: python gs_rom_test.py <SCUS_972.05>
"""
import struct, sys
from disasm import Image
from emu import Emu, Machine
import gs


class Logging(Machine):
    """A Machine that remembers every byte written, in order."""
    def __init__(self, img):
        super().__init__(img)
        self.writes = {}

    def wb(self, a, v):
        super().wb(a, v)
        self.writes[a & 0xffffffff] = v & 0xff


def capture(img, name, ints, floats=()):
    """Run until it stops, and keep whatever was written.

    These functions end by calling zSysFifoKick, which spins on a DMA status
    register waiting for hardware that does not exist here -- so the run
    never returns. That is fine and even informative: the packet is fully
    built before the kick, so the writes collected up to the hang are exactly
    the packet.
    """
    from emu import Unsupported
    _s, addr, size = img.func(name)
    m = Logging(img)
    e = Emu(img, m)
    try:
        e.run(addr, size, list(ints), list(floats), limit=200000)
    except Unsupported as ex:
        print(f'  (run stopped: {ex} -- expected, the DMA kick spins)')
    return m.writes


def runs(writes, minlen=16):
    """Group written bytes into contiguous regions."""
    out, cur = [], []
    for a in sorted(writes):
        if cur and a == cur[-1] + 1:
            cur.append(a)
        else:
            if len(cur) >= minlen:
                out.append((cur[0], bytes(writes[x] for x in cur)))
            cur = [a]
    if len(cur) >= minlen:
        out.append((cur[0], bytes(writes[x] for x in cur)))
    return out


def main(elf):
    img = Image(elf)
    REG, VAL = 0x47, 0x0000000000000001        # TEST_1 = ZTE on
    w = capture(img, 'SetGSReg', [REG, VAL])
    regions = runs(w)
    print(f'SetGSReg(0x{REG:02x}, 0x{VAL:x}) wrote '
          f'{len(w)} bytes in {len(regions)} contiguous regions\n')

    ok = False
    for base, blob in regions:
        if len(blob) < 48:
            continue
        print(f'region 0x{base:08x}, {len(blob)} bytes')
        for i in range(0, min(len(blob), 64), 16):
            q = blob[i:i + 16]
            lo, hi = struct.unpack('<QQ', q)
            print(f'  +{i:02x}  {hi:016x}_{lo:016x}')
        # The packet is a DMA tag, then VIF codes, then the GIF data.
        dma, = struct.unpack_from('<I', blob, 0)
        qwc, did = dma & 0xffff, (dma >> 28) & 7
        v0, v1 = struct.unpack_from('<II', blob, 8)
        print(f'\n  DMAtag  qwc={qwc} id={did} '
              f'({ {0:"refe",1:"cnt",2:"next",3:"ref"}.get(did, did) })')
        print(f'  VIFcode {v0:08x} cmd={v0 >> 24:02x}   '
              f'{v1:08x} cmd={v1 >> 24:02x} num={v1 & 0xffff}')
        assert did == 1, 'expected a CNT dma tag'
        assert v0 >> 24 == 0x11, 'expected VIF FLUSH'
        assert v1 >> 24 == 0x50, 'expected VIF DIRECT'
        assert (v1 & 0xffff) == qwc, 'DIRECT size must match the dma qwc'

        # Everything after the tag quadword is GIF data -- gs.py's job.
        print('\n  gs.py on the GIF payload:')
        for line in gs.decode(blob[16:16 + qwc * 16]):
            print('   ', line)
        t = gs.GifTag(*struct.unpack_from('<QQ', blob, 16))
        assert t.nloop == 1 and t.eop == 1, (t.nloop, t.eop)
        assert t.flg == gs.PACKED and t.nreg == 1, (t.flg, t.nreg)
        assert t.regs == [0xe], t.regs            # A+D
        d0, d1 = struct.unpack_from('<QQ', blob, 32)
        assert d1 & 0xff == REG, (hex(d1 & 0xff), hex(REG))
        assert d0 == VAL, (hex(d0), hex(VAL))
        print(f'\n  the register write round-trips: '
              f'{gs.AD[d1 & 0xff]} = 0x{d0:x}')
        ok = True
    if not ok:
        raise SystemExit('no packet region found -- the capture failed')
    print('\nok: gs.py decoded a packet built by the ROM itself')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'disc/SCUS_972.05')
