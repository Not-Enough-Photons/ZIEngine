"""Who calls whom. Direct `jal`/`j` edges across the whole image.

usage: python callers.py <elf> <0xADDR|name> [--callees]
"""
import bisect, collections, struct, sys
from symbols import functions, demangle
from disasm import Image


def edges(elf):
    """-> {callee_addr: {caller_sym, ...}} from every jal/j in the image."""
    img = Image(elf)
    fs = sorted(img.funcs, key=lambda x: x[1])
    starts = [a for _s, a, _z in fs]
    out = collections.defaultdict(set)
    blob = img.d[img.off:img.off + img.size]
    n = len(blob) // 4
    words = struct.unpack_from('<%dI' % n, blob, 0)
    fa = {a for _s, a, _z in fs}
    for k in range(n):
        w = words[k]
        op = w >> 26
        if op not in (2, 3):                      # j, jal
            continue
        pc = img.base + k * 4
        t = ((pc + 4) & 0xf0000000) | ((w & 0x03ffffff) << 2)
        if t not in fa:
            continue
        i = bisect.bisect_right(starts, pc) - 1
        if i < 0:
            continue
        s, a, z = fs[i]
        if pc < a + max(z, 4):
            out[t].add(s)
    return img, out


if __name__ == '__main__':
    img, e = edges(sys.argv[1])
    key = sys.argv[2]
    _s, addr, _z = img.func(key)
    cs = sorted(e.get(addr, ()))
    print(f'{len(cs)} callers of {key} (0x{addr:08x}):')
    for c in cs:
        cls, m = demangle(c)
        print(f'   {(cls + "::" + m) if cls else m}')
