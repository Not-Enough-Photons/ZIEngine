"""The game's top-level structure, annotated with what is already verified.

A port needs a spine before it needs breadth: where execution enters, what
the frame loop calls, and which of those are already proven against the ROM.
This walks the direct call graph down from the ELF entry point and prints the
tree, marking each node verified / mismatch / not yet attempted.

usage: python spine.py <SCUS_972.05> [root] [--depth N]
"""
import collections, json, os, struct, sys
from disasm import Image
from symbols import demangle
from callers import edges


def load_ledger():
    st = {}
    for p in ('decomp/lift_ledger.json', 'decomp/ledger.json'):
        if os.path.exists(p):
            for k, v in json.load(open(p)).items():
                if v.get('status') == 'verified' or k not in st:
                    st[k] = v.get('status')
    return st


def outgoing(elf):
    """caller_addr -> {callee_addr}, the reverse of callers.edges."""
    img, e = edges(elf)
    bysym = {s: a for s, a, _z in img.funcs}
    out = collections.defaultdict(set)
    for callee, callers in e.items():
        for c in callers:
            if c in bysym:
                out[bysym[c]].add(callee)
    return img, out


MARK = {'verified': '[OK]', 'mismatch': '[..]', 'unliftable': '[--]',
        'too_large': '[--]', None: '[  ]'}


def main(elf, root=None, maxdepth=3):
    img, out = outgoing(elf)
    st = load_ledger()
    if root:
        _s, addr, _z = img.func(root)
    else:
        addr, = struct.unpack_from('<I', img.d, 24)     # e_entry
    seen = set()
    tot = collections.Counter()

    def name(a):
        s, _z = img.byaddr.get(a, (f'sub_{a:08x}', 0))
        c, m = demangle(s)
        return f'{c}::{m}' if c else m

    def walk(a, d):
        if d > maxdepth or a in seen:
            return
        seen.add(a)
        n = name(a)
        sz = img.byaddr.get(a, ('', 0))[1]
        s = st.get(n)
        tot[s] += 1
        print(f'{"  " * d}{MARK.get(s, "[  ]")} {n[:60]:60s} {sz:6d}b')
        for t in sorted(out.get(a, ())):
            walk(t, d + 1)

    print(f'entry 0x{addr:08x}\n')
    walk(addr, 0)
    print(f'\n{sum(tot.values())} functions in this subtree:')
    for k, v in tot.most_common():
        print(f'   {MARK.get(k, "[  ]")} {k or "not attempted":14s} {v}')


if __name__ == '__main__':
    a = [x for x in sys.argv[1:] if not x.startswith('--')]
    dep = [x for x in sys.argv[1:] if x.startswith('--depth')]
    main(a[0] if a else 'disc/SCUS_972.05',
         a[1] if len(a) > 1 else None,
         int(dep[0].split('=')[1]) if dep else 3)
