"""Audit reCOM's hand-written headers against ground truth from the ROM.

reCOM's structs were reconstructed by eye in Ghidra. The May 13 2002 demo ELF
carries the real layouts in DWARF1, so every field list can be checked. Wrong
member sets and wrong order both silently corrupt pointer arithmetic, and
neither shows up as a compile error.

usage: python audit.py <SCUS_972.05> <recom/src> [ClassName]
"""
import re, sys, os, glob, difflib
from dwarf1 import parse, records, member_offset, typename

# "class CFoo" / "struct tag_Bar" up to the matching close. Brace-counting
# rather than regex nesting, so nested types don't truncate the body.
HEAD = re.compile(r'\b(class|struct)\s+([A-Za-z_]\w*)\s*(?::[^{;]*)?\{')

SKIP = re.compile(r'^\s*(?:public|private|protected|static|typedef|using|friend|'
                  r'virtual|inline|enum|class|struct|union|template|return|'
                  r'//|/\*|\#)')
# A data member declarator: "Type name", optional [dims]. The initialiser and
# any trailing comment are stripped before this runs -- reCOM writes both
# ("f32 m_gravity = 98.1f;", "CPnt3D m_velM; // world space").
MEMBER = re.compile(r'^\s*[A-Za-z_][\w:<>,\s\*&]*?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*$')


def bodies(text):
    """Yield (kind, name, body) for each class/struct with a real body."""
    for m in HEAD.finditer(text):
        i = m.end()
        depth, n = 1, len(text)
        while i < n and depth:
            c = text[i]
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            i += 1
        yield m.group(1), m.group(2), text[m.end():i - 1]


def declared(body):
    """-> [member names] in declaration order, skipping nested type bodies."""
    out, depth = [], 0
    for raw in body.splitlines():
        line = raw.split('//')[0]
        depth += line.count('{') - line.count('}')
        if depth > 0 or SKIP.match(line) or ';' not in line:
            continue
        decl = line.split(';')[0].split('=')[0]     # drop initialiser
        # drop a bitfield width, but not the '::' in a qualified type name
        decl = re.sub(r'(?<!:):\s*\d+\s*$', '', decl)
        if '(' in decl:                             # a method, not a member
            continue
        mm = MEMBER.match(decl)
        if mm:
            out.append(mm.group(1))
    return out


def recom_types(srcdir):
    """-> {ClassName: ([members], relpath)}"""
    out = {}
    for p in glob.glob(os.path.join(srcdir, '**', '*.h'), recursive=True):
        text = open(p, encoding='utf-8', errors='ignore').read()
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
        for _kind, name, body in bodies(text):
            mem = declared(body)
            if mem and (name not in out or len(mem) > len(out[name][0])):
                out[name] = (mem, os.path.relpath(p, srcdir))
    return out


def truth(elf):
    """-> {ClassName: [([(offset, name, type, bits)], byte_size), ...]}

    A name can have several distinct layouts: C struct names get reused across
    translation units (there are three unrelated AI_PARAMS). Keep every variant
    and let the caller pick the one that matches the source being audited.
    """
    roots, flat = parse(elf)
    out, seen = {}, {}
    for d in records(roots):
        n = d.name()
        if not n:
            continue
        mem = []
        for c in d.children:
            if c.tag != 'member':
                continue
            bits = None
            if 'bit_size' in c.at:
                bits = (c.at.get('bit_offset', 0), c.at['bit_size'])
            mem.append((member_offset(c), c.name(), typename(c, flat), bits))
        if not mem:
            continue
        key = (n, tuple(m[1] for m in mem), d.at.get('byte_size'))
        if key in seen:
            continue
        seen[key] = 1
        out.setdefault(n, []).append((mem, d.at.get('byte_size')))
    return out


def best_variant(variants, mine):
    """Pick the ROM layout whose member names overlap `mine` the most."""
    mineset = set(mine)
    scored = [(len(mineset & {m[1] for m in mem}), -abs(len(mem) - len(mine)), i)
              for i, (mem, _sz) in enumerate(variants)]
    scored.sort(reverse=True)
    return variants[scored[0][2]], len(variants)


def _place(o, bits):
    """Render a member's position, marking bitfields."""
    if o is None:
        return '  ?   '
    return f'0x{o:04x}:{bits[0]}+{bits[1]}' if bits else f'0x{o:04x}      '


def audit(elf, srcdir, only=None):
    T, R = truth(elf), recom_types(srcdir)
    shared = sorted(set(T) & set(R))
    if only:
        shared = [c for c in shared if only.lower() in c.lower()]

    rows = []
    for cls in shared:
        mine, path = R[cls]
        (real, size), nvar = best_variant(T[cls], mine)
        realnames = [n for _o, n, _t, _b in real]
        missing = [m for m in real if m[1] not in mine]
        extra = [n for n in mine if n not in realnames]
        # A near-identical name on both sides is a misspelling, not a gap.
        renames = []
        def _toks(s):
            return sorted(re.findall(r'[a-z0-9]+', s.lower()))
        for o, n, t, b in list(missing):
            hit = difflib.get_close_matches(n, extra, n=1, cutoff=0.8)
            if not hit:                       # catch word transpositions too
                hit = [e for e in extra if _toks(e) == _toks(n)][:1]
            if hit:
                renames.append((o, hit[0], n, t, b))
                missing.remove((o, n, t, b)); extra.remove(hit[0])
        common = [n for n in mine if n in realnames]
        order_ok = common == [n for n in realnames if n in mine]
        if missing or extra or renames or not order_ok:
            rows.append((len(missing), cls, path, size,
                         missing, extra, renames, order_ok, nvar))

    rows.sort(reverse=True)
    print(f'classes in both reCOM and the ROM: {len(shared)}')
    print(f'classes with a discrepancy:        {len(rows)}\n')
    for nmiss, cls, path, size, missing, extra, renames, order_ok, nvar in rows:
        flags = []
        if missing: flags.append(f'{len(missing)} missing')
        if renames: flags.append(f'{len(renames)} misspelled')
        if extra: flags.append(f'{len(extra)} unknown')
        if not order_ok: flags.append('ORDER')
        sz = f'0x{size:x}' if size else '?'
        amb = f'  (best of {nvar} ROM layouts)' if nvar > 1 else ''
        print(f'{cls}  [{", ".join(flags)}]  real size {sz}{amb}   {path}')
        for o, n, t, b in missing[:6]:
            print(f'    missing   {_place(o, b)}  {t} {n}')
        if len(missing) > 6:
            print(f'    ... and {len(missing) - 6} more missing')
        for o, wrong, right, t, b in renames[:6]:
            print(f'    RENAME    {_place(o, b)}  {wrong}  ->  {right}')
        for n in extra[:4]:
            print(f'    not in ROM          {n}')
        if not order_ok:
            print('    declaration order does not match the ROM')
        print()
    return rows


def demo():
    src = '''
public:
    void Load(_zrdr* reader);
    f32 m_gravity = 98.1f;
    CPnt3D m_velM; // Model-relative velocity
    f32 m_fallDist[3];
    std::vector<zdb::CNode*> m_DelayedNodes;
    u8 m_flags : 3;
    static s32 s_count;
    CQuat m_quat = CQuat();
    bool Tick(f32 dT);
'''
    got = declared(src)
    want = ['m_gravity', 'm_velM', 'm_fallDist', 'm_DelayedNodes',
            'm_flags', 'm_quat']
    assert got == want, f'got {got}'
    # a nested type's fields must not leak into the outer class
    assert declared('int a;\nstruct N {\n int inner;\n};\nint b;') == ['a', 'b']
    assert [n for _k, n, _b in bodies('class A { int x; };')] == ['A']
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        demo(); sys.exit()
    audit(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
