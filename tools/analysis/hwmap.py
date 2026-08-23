"""Find every function that touches PS2 graphics/DMA hardware registers.

"The renderer doesn't exist" is the main thing standing between a verified
decompilation and a port. On the PS2 there are no draw calls: the game fills
memory with GIF packets and kicks a DMA channel at them. So the renderer's
real entry points are exactly the functions that write the DMA and GS
control registers, and those can be found statically -- every access is a
`lui` of the 0x1000/0x1200 page followed by a load or store at a known
offset.

usage: python hwmap.py <SCUS_972.05>
"""
import bisect, collections, struct, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN
from symbols import functions, demangle

# EE hardware registers that matter for getting pixels out.
REGS = {
    0x10003000: 'VIF0_STAT', 0x10003800: 'VIF1_STAT',
    0x10004000: 'VIF0_FIFO', 0x10005000: 'VIF1_FIFO',
    0x10006000: 'GIF_FIFO',
    0x10003000 + 0x20: 'GIF_STAT',
    0x10008000: 'D0_CHCR(VIF0)', 0x10009000: 'D1_CHCR(VIF1)',
    0x1000a000: 'D2_CHCR(GIF)', 0x1000b000: 'D3_CHCR(fromIPU)',
    0x1000b400: 'D4_CHCR(toIPU)', 0x1000c000: 'D5_CHCR(SIF0)',
    0x1000c400: 'D6_CHCR(SIF1)', 0x1000c800: 'D7_CHCR(SIF2)',
    0x1000d000: 'D8_CHCR(fromSPR)', 0x1000d400: 'D9_CHCR(toSPR)',
    0x1000e000: 'D_CTRL', 0x1000e010: 'D_STAT', 0x1000e020: 'D_PCR',
    0x1000f000: 'INTC_STAT', 0x1000f010: 'INTC_MASK',
    0x12000000: 'GS_PMODE', 0x12000010: 'GS_SMODE1', 0x12000020: 'GS_SMODE2',
    0x12000070: 'GS_DISPFB1', 0x12000080: 'GS_DISPLAY1',
    0x12000090: 'GS_DISPFB2', 0x120000a0: 'GS_DISPLAY2',
    0x120000e0: 'GS_BGCOLOR', 0x12001000: 'GS_CSR', 0x12001010: 'GS_IMR',
}
PAGE = {0x1000: 'EE hardware', 0x1001: 'EE hardware', 0x1200: 'GS privileged'}
MEM = ('lw', 'sw', 'ld', 'sd', 'lq', 'sq', 'lb', 'lbu', 'lh', 'lhu', 'sb',
       'sh', 'lwu', 'lwc1', 'swc1')


def scan(elf):
    fs = sorted(functions(elf), key=lambda x: x[1])
    d = open(elf, 'rb').read()
    from disasm import Image
    img = Image(elf)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)
    hits = collections.defaultdict(collections.Counter)
    for sym, a, sz in fs:
        if not sz:
            continue
        code = img.read(a, sz)
        hi = {}
        for i in range(0, len(code) - 3, 4):
            g = list(md.disasm(code[i:i + 4], a + i))
            if not g:
                hi.clear()
                continue
            ins = g[0]
            ops = [x.strip() for x in ins.op_str.split(',')]
            if ins.mnemonic == 'lui' and len(ops) == 2:
                v = int(ops[1], 0)
                if v in PAGE:
                    hi[ops[0]] = v << 16
                else:
                    hi.pop(ops[0], None)
                continue
            if ins.mnemonic in MEM and len(ops) == 2 and '(' in ops[1]:
                off, _, base = ops[1].partition('(')
                base = base.rstrip(')')
                if base in hi:
                    addr = hi[base] + (int(off, 0) if off.strip() else 0)
                    name = REGS.get(addr & ~0xf if addr not in REGS else addr)
                    hits[sym][name or f'{addr:#010x}'] += 1
            # anything that writes the base register kills the pairing
            elif ops and ops[0].startswith('$'):
                hi.pop(ops[0], None)
    return hits


if __name__ == '__main__':
    hits = scan(sys.argv[1])
    tot = collections.Counter()
    for sym, c in hits.items():
        tot.update(c)
    print(f'{len(hits)} functions touch EE hardware registers directly\n')
    print('most-used registers:')
    for k, n in tot.most_common(20):
        print(f'  {n:5d}  {k}')
    print('\nfunctions, by how much hardware they touch:')
    rank = sorted(hits.items(), key=lambda kv: -sum(kv[1].values()))
    for sym, c in rank[:25]:
        cls, meth = demangle(sym)
        full = f'{cls}::{meth}' if cls else meth
        top = ' '.join(f'{k}x{v}' for k, v in c.most_common(4))
        print(f'  {sum(c.values()):4d}  {full[:44]:44s} {top}')
