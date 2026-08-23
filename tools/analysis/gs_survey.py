"""Every GS register SOCOM actually writes, taken from the ROM's own packets.

A port has to reimplement the Graphics Synthesizer, and the GS has far more
registers and modes than any one game uses. Rather than guess at the subset,
run each of the game's packet builders in the interpreter, capture the bytes
they emit, and decode them. What comes out is the renderer's real feature
list -- the minimum a replacement has to support.

Builders end by calling zSysFifoKick, which spins on DMA hardware, so each
run is expected to stop at the step limit with the packet already written.

usage: python gs_survey.py <SCUS_972.05>
"""
import collections, struct, sys
from disasm import Image
from emu import Emu, Unsupported
from symbols import demangle
import gs
from gs_rom_test import Logging, runs
from callers import edges

DMA_ID = {0: 'refe', 1: 'cnt', 2: 'next', 3: 'ref', 4: 'refs', 5: 'call',
          6: 'ret', 7: 'end'}
VIF = {0x00: 'NOP', 0x01: 'STCYCL', 0x02: 'OFFSET', 0x03: 'BASE',
       0x04: 'ITOP', 0x05: 'STMOD', 0x06: 'MSKPATH3', 0x07: 'MARK',
       0x10: 'FLUSHE', 0x11: 'FLUSH', 0x13: 'FLUSHA', 0x14: 'MSCAL',
       0x15: 'MSCALF', 0x17: 'MSCNT', 0x20: 'STMASK', 0x30: 'STROW',
       0x31: 'STCOL', 0x4a: 'MPG', 0x50: 'DIRECT', 0x51: 'DIRECTHL'}


def gif_payloads(m, base, blob):
    """Walk a DMA/VIF wrapped buffer, yielding the GIF quadwords inside.

    The game submits through VIF1: a DMA tag, VIF codes in the tag's spare
    64 bits, and DIRECT hands the following quadwords to the GIF. A `ref`
    tag points somewhere else, so follow it through the machine's memory.
    """
    if len(blob) < 16:
        return
    dma, = struct.unpack_from('<I', blob, 0)
    qwc, did = dma & 0xffff, (dma >> 28) & 7
    addr, = struct.unpack_from('<I', blob, 4)
    v0, v1 = struct.unpack_from('<II', blob, 8)
    yield ('tag', qwc, did, addr, v0, v1)
    n = v1 & 0xffff if (v1 >> 24) in (0x50, 0x51) else qwc
    if did in (3, 4, 0):                       # ref/refs/refe: data is elsewhere
        if addr and n:
            yield ('gif', bytes(m.load(addr + i, 1) for i in range(n * 16)))
    elif len(blob) >= 16 + n * 16:
        yield ('gif', blob[16:16 + n * 16])


def survey(elf):
    img = Image(elf)
    _i, e = edges(elf)
    _s, kick, _z = img.func('zSysFifoKick')
    builders = sorted(e.get(kick, ()))
    regs = collections.Counter()
    prims = collections.Counter()
    rows = []
    bysym = {s2: (a2, z2) for s2, a2, z2 in img.funcs}
    # Several builders emit a `ref` DMA tag pointing at a packet that was
    # assembled once during video init. Run the init functions first and keep
    # their memory, or those references dangle and the survey sees nothing.
    warm = {}
    for boot in ('zVid_Init', 'zVid_Open', 'zvid_SetVideoMode', 'CPipe::Init'):
        try:
            _s3, a3, z3 = img.func(boot)
        except SystemExit:
            continue
        mb = Logging(img)
        mb.mem.update(warm)
        try:
            Emu(img, mb).run(a3, z3, [0, 0, 0, 0], [0.0], limit=200000)
        except Exception:
            pass
        warm.update(mb.mem)
    print(f'(warm-up wrote {len(warm)} bytes of global state)')
    for sym in builders:
        if sym not in bysym:
            continue
        a, sz = bysym[sym]
        if not sz:
            continue
        m = Logging(img)
        m.mem.update(warm)          # globals the init pass filled in
        em = Emu(img, m)
        try:
            em.run(a, sz, [0, 0, 0, 0], [0.0], limit=120000)
        except Unsupported:
            pass
        except Exception:
            pass
        found = []
        for base, blob in runs(m.writes, 16):
            for item in gif_payloads(m, base, blob):
                if item[0] != 'gif':
                    continue
                data = item[1]
                for line in gs.decode(data, limit=32):
                    if 'A+D' in line:
                        r = line.split('A+D')[1].split('=')[0].strip()
                        regs[r] += 1
                        found.append(r)
                    elif 'PRIM=' in line:
                        p = line.split('PRIM=')[1].strip()
                        prims[p.split(',')[0]] += 1
                        found.append('PRIM:' + p)
        cls, meth = demangle(sym)
        rows.append(((f'{cls}::{meth}' if cls else meth), found))
    return rows, regs, prims


if __name__ == '__main__':
    rows, regs, prims = survey(sys.argv[1] if len(sys.argv) > 1
                               else 'disc/SCUS_972.05')
    print('packet builders and the GS state they set:\n')
    for name, found in rows:
        if found:
            print(f'  {name[:42]:42s} {", ".join(found[:6])}')
    print(f'\nGS registers the renderer writes ({len(regs)} distinct):')
    for k, n in regs.most_common():
        print(f'  {n:4d}  {k}')
    if prims:
        print('\nprimitive types seen:')
        for k, n in prims.most_common():
            print(f'  {n:4d}  {k}')
