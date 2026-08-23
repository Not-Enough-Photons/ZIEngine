"""Recover the original Zipper source tree from the ELF's Metrowerks .debug section."""
import re, sys, collections
from symbols import sections

BS = chr(92)
# built from chr(92) so no literal backslash appears in this source
PATH_RE = re.compile(('[A-Za-z]:' + BS + BS + '[ -~]{4,}').encode())
SRC_RE = re.compile(r'[.](c|cpp|h|hpp|s)$', re.I)

def paths(elf):
    d = open(elf, 'rb').read()
    S = sections(d)
    o, sz = S['.debug'][4], S['.debug'][5]
    blob = d[o:o + sz]
    out = set()
    for m in PATH_RE.finditer(blob):
        p = m.group(0).decode('latin-1')
        if SRC_RE.search(p):
            out.add(p)
    return out

if __name__ == '__main__':
    ps = paths(sys.argv[1])
    print(f'unique original source files: {len(ps)}\n')
    dirs = collections.Counter(BS.join(p.split(BS)[:-1]) for p in ps)
    print('=== original directory tree ===')
    for d, n in sorted(dirs.items()):
        print(f'  {n:4d}  {d}')
