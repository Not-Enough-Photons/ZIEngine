"""How many functions branch into another branch's delay slot?

lift.py folds a delay slot into the branch that owns it, which consumes that
address and drops its label. MIPS permits a branch to target a delay slot,
and hand-written assembly does it. The fix emits a second copy of the slot
behind its own label -- but the regression gate only proves the eleven
functions in it, so this measures how much code the pattern actually touches.

usage: python delayscan.py <SCUS_972.05>
"""
import sys
from disasm import Image
from emu import Machine
from symbols import demangle

BRANCHY = {'b', 'j', 'jal', 'jalr', 'jr', 'bal', 'beq', 'bne', 'beqz', 'bnez',
           'blez', 'bgtz', 'bltz', 'bgez', 'bc1t', 'bc1f'}


def branches(mn):
    base = mn[:-1] if mn.endswith('l') and mn[:-1] in BRANCHY else mn
    return base in BRANCHY


def scan(elf):
    img = Image(elf)
    m = Machine(img)
    out = []
    for sym, addr, size in img.funcs:
        if not size:
            continue
        ins, targets, slots = {}, set(), set()
        try:
            for pc in range(addr, addr + size, 4):
                ins[pc] = m.ins(pc)
        except Exception:
            continue
        for pc, (mn, ops) in ins.items():
            if not branches(mn):
                continue
            slots.add(pc + 4)
            for tok in (ops or '').split(','):
                tok = tok.strip()
                if tok.startswith('0x'):
                    try:
                        t = int(tok, 0)
                    except ValueError:
                        continue
                    if addr <= t < addr + size:
                        targets.add(t)
        bad = targets & slots
        if bad:
            out.append((sym, addr, sorted(bad)))
    return img, out


if __name__ == '__main__':
    img, out = scan(sys.argv[1] if len(sys.argv) > 1 else 'disc/SCUS_972.05')
    tot = sum(len(b) for _s, _a, b in out)
    print(f'{len(out)} functions branch into a delay slot ({tot} sites)\n')
    for sym, addr, bad in out[:25]:
        cls, meth = demangle(sym)
        n = f'{cls}::{meth}' if cls else meth
        print(f'  0x{addr:08x}  {n[:46]:46s} {len(bad)} site(s)')
