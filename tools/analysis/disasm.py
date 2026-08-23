"""Produce a decompilation work order for one function in SCUS_972.05.

Everything needed to write the C++ by hand, in one place: the R5900
disassembly, every call target resolved to a demangled name, referenced
globals and string literals resolved via .symtab, and the DWARF signature
when the compiler emitted one.

usage: python disasm.py <SCUS_972.05> <FunctionName|0xADDR>
"""
import bisect, re, struct, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN
from symbols import sections, functions, demangle


_VT_CACHE = {}


def vtables(img, minslots=4):
    """Find vtables: runs of consecutive words that are all function entries.

    Objects filled with random bytes have a garbage vtable pointer, so every
    virtual call jumps nowhere and the function cannot be exercised at all.
    Seeding a real vtable makes them runnable -- the specific table need not
    be the class's own, since what is being verified is that the lifted code
    dispatches the same way the ROM does.
    """
    key = id(img)
    if key in _VT_CACHE:
        return _VT_CACHE[key]
    fa = {a for _s, a, _z in img.funcs}
    blob = img.d[img.off:img.off + img.size]
    n = len(blob) // 4
    words = struct.unpack_from('<%dI' % n, blob, 0)
    out, start, cnt = [], None, 0
    for k in range(n):
        if words[k] in fa:
            if start is None:
                start = k
            cnt += 1
        else:
            if cnt >= minslots:
                out.append(img.base + start * 4)
            start, cnt = None, 0
    if cnt >= minslots:
        out.append(img.base + start * 4)
    _VT_CACHE[key] = out
    return out


def _objects(d, S):
    """-> sorted [(addr, size, name)] for STT_OBJECT symbols (globals)."""
    symo, symsz = S['.symtab'][4], S['.symtab'][5]
    sto = S['.strtab'][4]
    out = []
    for i in range(symsz // 16):
        nameo, val, size, info, _o, _sh = struct.unpack_from('<IIIBBH', d, symo + i * 16)
        if info & 0xf == 1 and val:
            out.append((val, size,
                        d[sto + nameo:d.index(b'\x00', sto + nameo)].decode('latin-1')))
    out.sort()
    return out


class Image:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        self.S = sections(self.d)
        _n, _t, _f, addr, off, size = self.S['main'][:6]
        self.base, self.off, self.size = addr, off, size
        self.funcs = functions(path)
        self.byaddr = {a: (s, sz) for s, a, sz in self.funcs}
        self.objs = _objects(self.d, self.S)
        self.objaddrs = [o[0] for o in self.objs]

    def read(self, addr, n):
        p = self.off + (addr - self.base)
        return self.d[p:p + n]

    def func(self, key):
        """Find a function by 0xADDR or by (demangled) name substring."""
        if isinstance(key, str) and key.startswith('0x'):
            a = int(key, 16)
            s, sz = self.byaddr.get(a, ('sub_%08x' % a, 0x200))
            return s, a, sz
        hits = []
        for s, a, sz in self.funcs:
            c, m = demangle(s)
            full = f'{c}::{m}' if c else m
            if key == full or key == m or key.lower() in full.lower():
                hits.append((s, a, sz, full))
        if not hits:
            raise SystemExit(f'no function matching {key!r}')
        hits.sort(key=lambda h: len(h[3]))
        return hits[0][:3]

    def label(self, addr):
        """Name an address: exact function, or global +offset."""
        if addr in self.byaddr:
            c, m = demangle(self.byaddr[addr][0])
            return f'{c}::{m}' if c else m
        i = bisect.bisect_right(self.objaddrs, addr) - 1
        if i >= 0:
            a, size, name = self.objs[i]
            if addr < a + max(size, 1):
                return name if addr == a else f'{name}+{addr - a:#x}'
        return None

    def cstring(self, addr, limit=72):
        try:
            b = self.read(addr, limit)
        except Exception:
            return None
        e = b.find(b'\x00')
        if e <= 0:
            return None
        s = b[:e]
        if all(32 <= c < 127 or c in (9, 10) for c in s):
            return s.decode('latin-1')
        return None


def signature(elf, name, low_pc=None):
    """DWARF formal_parameter list for a function, if the CU had debug info.

    Matched on AT_low_pc when available -- names alone collide badly (there
    are many unrelated Parse/Tick/Init methods).
    """
    try:
        from dwarf1 import parse, typename
    except Exception:
        return None
    roots, flat = parse(elf)
    stack = list(roots)
    while stack:
        d = stack.pop()
        if d.tag in ('subroutine', 'global_subroutine', 'subprogram') and (
                d.at.get('low_pc') == low_pc if low_pc else d.name() == name):
            ps = [f'{typename(c, flat)} {c.name()}'
                  for c in d.children if c.tag == 'formal_parameter']
            lv = [f'{typename(c, flat)} {c.name()}'
                  for c in d.children if c.tag == 'local_variable']
            return ps, lv
        stack.extend(d.children)
    return None


def work_order(elf, key):
    img = Image(elf)
    sym, addr, size = img.func(key)
    cls, meth = demangle(sym)
    full = f'{cls}::{meth}' if cls else meth
    print(f'=== {full} ===')
    print(f'mangled  {sym}')
    print(f'addr     0x{addr:08x}   size {size} bytes ({size // 4} instructions)')

    sig = signature(elf, meth, addr)
    if sig:
        ps, lv = sig
        print(f'params   ({", ".join(ps) if ps else "void"})')
        if lv:
            print(f'locals   {"; ".join(lv[:8])}')
    print()

    code = img.read(addr, size)
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)
    calls, lines = [], []
    hi = {}                       # reg -> lui immediate, to fold lui/addiu pairs
    # Decode one word at a time: a single R5900-only opcode must not halt
    # the whole stream the way Cs.disasm() does.
    for i in range(0, len(code) - 3, 4):
        got = list(md.disasm(code[i:i + 4], addr + i))
        if not got:
            w, = struct.unpack_from('<I', code, i)
            lines.append(f'  {addr + i:08x}  .word     0x{w:08x}   ; R5900-only')
            continue
        ins = got[0]
        note = ''
        if ins.mnemonic in ('jal', 'j', 'bal') and ins.op_str.startswith('0x'):
            t = int(ins.op_str, 0)
            nm = img.label(t)
            if nm:
                note = f'   ; {nm}'
                if ins.mnemonic == 'jal':
                    calls.append(nm)
        m = re.match(r'(\$\w+), (0x[0-9a-f]+)$', ins.op_str)
        if ins.mnemonic == 'lui' and m:
            hi[m.group(1)] = int(m.group(2), 16) << 16
        m = re.match(r'(\$\w+), (\$\w+), (-?(?:0x)?[0-9a-f]+)$', ins.op_str)
        if ins.mnemonic in ('addiu', 'ori') and m and m.group(2) in hi:
            val = hi[m.group(2)] + int(m.group(3), 0)
            s = img.cstring(val)                # the literal beats the symbol:
            lab = img.label(val)                # anon strings are named "@1925"
            if s:
                note = f'   ; "{s}"'
            elif lab:
                note = f'   ; {lab}'
        lines.append(f'  {ins.address:08x}  {ins.mnemonic:<9s} {ins.op_str}{note}')
    print('\n'.join(lines))

    if calls:
        print(f'\ncalls ({len(calls)} sites, {len(set(calls))} distinct):')
        for c in sorted(set(calls)):
            print(f'   {c}')
    return img, addr, size


if __name__ == '__main__':
    work_order(sys.argv[1], sys.argv[2])
