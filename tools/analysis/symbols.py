"""Read SCUS_972.05's symbol table and demangle Metrowerks MIPS C++ names.

The May 13 2002 demo ELF is an unstripped debug build: .symtab has 9,703
STT_FUNC entries with address + size, which is everything needed to measure
decompilation progress the way real decomp projects do (weighted by bytes).
"""
import re, struct

def sections(d):
    shoff, = struct.unpack_from('<I', d, 0x20)
    entsz, num, stridx = struct.unpack_from('<HHH', d, 0x2e)
    raw = [struct.unpack_from('<10I', d, shoff + i * entsz) for i in range(num)]
    base = raw[stridx][4]
    def nm(x):
        return d[base + x:d.index(b'\x00', base + x)].decode('latin-1')
    return {nm(r[0]): r for r in raw}

def functions(path):
    """-> list of (mangled, addr, size) for every STT_FUNC symbol."""
    d = open(path, 'rb').read()
    S = sections(d)
    symo, symsz = S['.symtab'][4], S['.symtab'][5]
    sto = S['.strtab'][4]
    out = []
    for i in range(symsz // 16):
        nameo, val, size, info, _o, _sh = struct.unpack_from('<IIIBBH', d, symo + i * 16)
        if info & 0xf == 2:
            out.append((d[sto + nameo:d.index(b'\x00', sto + nameo)].decode('latin-1'),
                        val, size))
    return out

# <len><name>, optionally preceded by Q<n> for nested scopes (Q23std5deque)
_SCOPE = re.compile(r'^(?:Q(\d))?(\d+)')

def _scopes(spec):
    """Parse a Metrowerks scope spec -> list of names, or None."""
    m = _SCOPE.match(spec)
    if not m:
        return None
    count = int(m.group(1)) if m.group(1) else 1
    i = m.end(1) if m.group(1) else 0
    names = []
    for _ in range(count):
        m2 = re.compile(r'(\d+)').match(spec, i)
        if not m2:
            return None
        n = int(m2.group(1)); i = m2.end()
        names.append(spec[i:i + n]); i += n
    return names

def demangle(sym):
    """-> (class_or_None, method). Unmangled C names pass through."""
    special = {'ct': '<ctor>', 'dt': '<dtor>'}
    for m in re.finditer(r'__', sym):
        head, tail = sym[:m.start()], sym[m.end():]
        if tail.startswith('F'):                       # free function
            if head:
                return None, head
            continue
        sc = _scopes(tail)
        if sc is None:
            continue
        if head.startswith('__') or head == '':        # __ct / __dt / operators
            head = special.get(sym[m.end() - 2:m.start()] if False else head.strip('_'), head)
        return '::'.join(sc), special.get(head.strip('_'), head) if head else '<ctor>'
    return None, sym

def demo():
    cases = {
        'ComputeNextPosition__10CZSealBodyFf': ('CZSealBody', 'ComputeNextPosition'),
        'RenderNode__5CPipeFPQ23zdb5CNode':    ('CPipe', 'RenderNode'),
        'zAnimLoadObjectMotion__FP5_zrdr':     (None, 'zAnimLoadObjectMotion'),
        'RegisterPackets':                     (None, 'RegisterPackets'),
        '__ct__10CZSealBodyFPQ23zdb5CNode':    ('CZSealBody', '<ctor>'),
        'get_mode__6sealaiFPCc':               ('sealai', 'get_mode'),
        'SetRegionType__7CAiMapsFPCQ26CAiMap6region': ('CAiMaps', 'SetRegionType'),
    }
    for sym, want in cases.items():
        got = demangle(sym)
        assert got == want, f'{sym}: got {got}, want {want}'
    assert _scopes('Q23zdb5CNode') == ['zdb', 'CNode']
    print('ok')

if __name__ == '__main__':
    demo()
