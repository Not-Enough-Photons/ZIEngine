"""Measure reCOM's coverage of SCUS_972.05 by name-matching against .symtab.

Counts a function as "attempted" when reCOM defines a function of the same
demangled Class::Method name with a non-empty body. Name identity is not
correctness -- this is an UPPER BOUND on progress, not a match percentage.

usage: python progress.py <SCUS_972.05> <recom/src>
"""
import re, sys, glob, os, collections
from symbols import functions, demangle

# ReturnType Class::Method(...) {  /  ReturnType freeFunc(...) {
DEF = re.compile(
    r'\n[A-Za-z_][\w:<>\*&,\s]*?(?:([A-Za-z_]\w*)\s*::\s*)?(~?[A-Za-z_]\w*|operator\s*\S{1,2})'
    r'\s*\([^;{]*\)\s*(?:const\s*)?\{(.*?)\n\}', re.S)

def implemented(srcdir):
    """-> {(class|None, method): (has_body, module)}"""
    out = {}
    for p in glob.glob(os.path.join(srcdir, '**', '*.cpp'), recursive=True):
        mod = os.path.basename(os.path.dirname(p))
        for m in DEF.finditer(open(p, encoding='utf-8', errors='ignore').read()):
            cls, meth, body = m.group(1), m.group(2), m.group(3)
            b = re.sub(r'//.*', '', body)
            b = re.sub(r'/\*.*?\*/', '', b, flags=re.S)
            if meth.startswith('~'):
                meth = '<dtor>'
            elif cls and meth == cls:
                meth = '<ctor>'
            key = (cls, meth)
            has = bool(b.strip())
            if key not in out or has:           # prefer the implemented one
                out[key] = (has, mod)
    return out

def main(elf, srcdir):
    syms = functions(elf)
    impl = implemented(srcdir)
    by_name = collections.defaultdict(list)
    for cls, meth in impl:
        by_name[meth].append(cls)

    tot_n = len(syms); tot_b = sum(s for _, _, s in syms)
    hit_n = hit_b = stub_n = stub_b = 0
    hits = []
    for sym, addr, size in syms:
        cls, meth = demangle(sym)
        for key in ((cls, meth), (None, meth)):
            if key in impl:
                has, mod = impl[key]
                if has:
                    hit_n += 1; hit_b += size; hits.append((mod, size))
                else:
                    stub_n += 1; stub_b += size
                break

    print(f'ROM functions          {tot_n:6d}   {tot_b:10,d} bytes')
    print(f'reCOM has a body for   {hit_n:6d}   {hit_b:10,d} bytes')
    print(f'reCOM has an empty stub{stub_n:6d}   {stub_b:10,d} bytes')
    print()
    print(f'COVERAGE (upper bound)  by count {100*hit_n/tot_n:5.2f}%'
          f'   by bytes {100*hit_b/tot_b:5.2f}%')
    print()
    agg = collections.Counter(); cnt = collections.Counter()
    for mod, size in hits:
        agg[mod] += size; cnt[mod] += 1
    print('top modules by bytes attempted:')
    for mod, b in agg.most_common(12):
        print(f'   {mod:14s} {cnt[mod]:4d} fns  {b:8,d} b')
    unmatched = len(impl) - hit_n - stub_n
    print(f'\nreCOM definitions with no ROM symbol: {unmatched} '
          f'(helpers/PC-only/renamed)')

if __name__ == '__main__':
    main(*sys.argv[1:3])
