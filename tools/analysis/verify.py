"""Cross-check a decompiled reader-parser against the ROM function it replaces.

No MIPS toolchain here, so this is not a byte-match. It is the next best
oracle for this very common shape of function: pull every
(reader key, helper called, mask bit set) triple out of the disassembly, pull
the same out of the C++, and diff. A dropped field, a typo'd key, a wrong bit
or the wrong helper all fail loudly.

usage: python verify.py <SCUS_972.05> <Function> <decomp.cpp>
"""
import re, struct, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN
from disasm import Image


def from_rom(elf, key):
    """-> [(reader_key, helper, mask_bit)] in call order.

    Delegates to gen_parser.trace so both tools share one reading of the
    machine code -- notably its branch-delay-slot handling, which an
    independent second implementation got wrong.
    """
    from gen_parser import trace
    img = Image(elf)
    _sym, addr, size = img.func(key)
    return [(k, helper, bit) for _scope, k, helper, _off, bit
            in trace(img, addr, size) if k]


CALL = re.compile(r'(zrdr_\w+)\s*\(\s*\w+\s*,\s*"(\w+)"')   # keys are mixed case
BIT = re.compile(r'mask\s*\|=\s*(0x[0-9a-fA-F]+)')


def from_cpp(path):
    """-> [(reader_key, helper, mask_bit)] in source order."""
    out = []
    for line in open(path, encoding='utf-8'):
        line = line.split('//')[0]
        c = CALL.search(line)
        if c:
            out.append([c.group(2), c.group(1), None])
        b = BIT.search(line)
        if b and out and out[-1][2] is None:
            out[-1][2] = int(b.group(1), 16)
    return [tuple(t) for t in out]


def call_sites(elf, func):
    """Count zrdr_* call sites by scanning raw jal opcodes.

    Deliberately independent of trace(): from_rom() shares the generator's
    tracer, so a tracer that silently gives up would make both sides empty and
    "pass". This second opinion needs no state tracking, so it catches that.
    """
    img = Image(elf)
    _s, addr, size = img.func(func)
    code = img.read(addr, size)
    n = 0
    for i in range(0, len(code) - 3, 4):
        w, = struct.unpack_from('<I', code, i)
        if (w >> 26) == 3:                                   # jal
            t = ((addr + i) & 0xf0000000) | ((w & 0x3ffffff) << 2)
            nm = img.label(t)
            if nm and nm.startswith('zrdr_find') and nm != 'zrdr_findtag':
                n += 1
    return n


def verify(elf, func, cpp):
    rom, mine = from_rom(elf, func), from_cpp(cpp)
    raw = call_sites(elf, func)
    if raw != len(rom):
        print(f'  TRACER   {func}: {raw} zrdr_find* call sites in the machine '
              f'code but the tracer recovered {len(rom)} -- output is incomplete')
        return max(raw - len(rom), 1)
    # findtag has no mask bit and only scopes the block; compare the rest
    rom = [t for t in rom if t[1] != 'zrdr_findtag']
    mine = [t for t in mine if t[1] != 'zrdr_findtag']
    R, M = {t[0]: t for t in rom}, {t[0]: t for t in mine}

    def _b(v):                      # not every parser keeps a mask word
        return 'none' if v is None else f'{v:#x}'

    bad = 0
    for k in sorted(set(R) | set(M)):
        if k not in M:
            print(f'  MISSING  {k}: in ROM ({R[k][1]}, bit {_b(R[k][2])}), not in C++')
            bad += 1
        elif k not in R:
            print(f'  INVENTED {k}: in C++, not in ROM'); bad += 1
        elif R[k] != M[k]:
            print(f'  WRONG    {k}: ROM {R[k][1]} bit {_b(R[k][2])}  '
                  f'!= C++ {M[k][1]} bit {_b(M[k][2])}'); bad += 1
    print(f'{len(R)} reader fields in ROM, {len(M)} in C++, {bad} mismatches')
    return bad


def demo():
    import tempfile, os
    src = ('if (zrdr_findreal(r, "alpha", &alpha)) mask |= 0x0001;\n'
           'if (zrdr_finduint(r, "beta", &beta))   mask |= 0x0002;\n')
    fd, p = tempfile.mkstemp(suffix='.cpp'); os.write(fd, src.encode()); os.close(fd)
    assert from_cpp(p) == [('alpha', 'zrdr_findreal', 1),
                           ('beta', 'zrdr_finduint', 2)], from_cpp(p)
    os.unlink(p)
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 4:
        demo()
    else:
        sys.exit(1 if verify(sys.argv[1], sys.argv[2], sys.argv[3]) else 0)
