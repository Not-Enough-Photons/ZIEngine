"""Generate C++ for the ROM's reader-parser functions, straight from the code.

13 functions in SCUS_972.05 are almost entirely
    zrdr_findX(reader, "key", &field) -> set a mask bit
which is regular enough to emit mechanically instead of hand-writing. Nested
( TAG ( ... ) ) scopes are tracked by following the register that receives
zrdr_findtag's return value.

Output still needs a human eye for field names -- the ROM gives offsets, not
identifiers -- so members are emitted as their struct offsets when a layout
is not supplied.

usage: python gen_parser.py <SCUS_972.05> <Function> [StructName]
"""
import re, struct, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN
from disasm import Image
from symbols import demangle

MD = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)


def fields_at(elf, struct_name):
    """-> {offset: (name, type)} for a struct, from DWARF."""
    if not struct_name:
        return {}
    from dwarf1 import parse, records, member_offset, typename
    roots, flat = parse(elf)
    best = None
    for d in records(roots):
        if d.name() == struct_name:
            mem = {member_offset(c): (c.name(), typename(c, flat))
                   for c in d.children if c.tag == 'member'}
            if mem and (best is None or len(mem) > len(best)):
                best = mem
    return best or {}


def decode(img, addr, size):
    """-> [(addr, mnemonic, op_str)], one entry per word, None-safe."""
    code = img.read(addr, size)
    out = []
    for i in range(0, len(code) - 3, 4):
        got = list(MD.disasm(code[i:i + 4], addr + i))
        out.append((addr + i, got[0].mnemonic, got[0].op_str) if got
                   else (addr + i, '.word', ''))
    return out


def trace(img, addr, size):
    """Walk the function, yielding (scope, key, helper, out_off, bit).

    MIPS runs the instruction after a jal BEFORE the jump, and Metrowerks
    parks argument setup there -- in HEALTH_PARAMS::Parse the "health" string
    is loaded in the delay slot of its own findtag call. So each call is
    resolved only after its delay slot has been applied.
    """
    code = img.read(addr, size)
    hi = {}          # reg -> lui value
    scope = {}       # reg -> tag name currently held
    outoff = {}      # reg -> struct offset (from `addiu $a2, $sN, off`)
    key = None       # pending string literal
    cur_a0 = None    # reg last moved into $a0
    cur_a2 = None    # offset last put in $a2
    rows = []
    pend_tag = None
    ins = decode(img, addr, size)

    def effect(mn, op):
        """Apply one non-call instruction's effect on tracked state."""
        nonlocal key, cur_a0, cur_a2, pend_tag
        m = re.match(r'(\$\w+), (0x[0-9a-f]+)$', op)
        if mn == 'lui' and m:
            hi[m.group(1)] = int(m.group(2), 16) << 16
            return
        m = re.match(r'(\$\w+), (\$\w+), (-?(?:0x)?[0-9a-f]+)$', op)
        if mn in ('addiu', 'ori') and m:
            dst, src, imm = m.group(1), m.group(2), int(m.group(3), 0)
            if src in hi:                       # string literal address
                s = img.cstring(hi[src] + imm)
                if s and re.fullmatch(r'[A-Za-z0-9_]+', s):
                    key = s
            elif dst == '$a2':                  # &this->field
                cur_a2 = imm
            return
        m = re.match(r'(\$\w+), (\$\w+)$', op)
        if mn == 'move' and m:
            dst, src = m.group(1), m.group(2)
            if dst == '$a0':
                cur_a0 = src
            elif dst == '$a2':                  # move, not addiu -> offset 0
                cur_a2 = 0
            elif src == '$v0' and pend_tag:     # capture findtag result
                scope[dst] = pend_tag; pend_tag = None

    i = 0
    while i < len(ins):
        _a, mn, op = ins[i]
        if mn == 'jal' and op.startswith('0x'):
            if i + 1 < len(ins):                # delay slot runs first
                effect(ins[i + 1][1], ins[i + 1][2])
            nm = img.label(int(op, 0))
            if nm and nm.startswith('zrdr_'):
                if nm == 'zrdr_findtag':
                    pend_tag = key
                else:
                    rows.append([scope.get(cur_a0), key, nm, cur_a2, None])
                key = None
            i += 2                              # skip the delay slot
            continue
        m = re.match(r'(\$\w+), \1, (0x[0-9a-f]+|\d+)$', op)
        if mn == 'ori' and m and rows and rows[-1][4] is None:
            rows[-1][4] = int(m.group(2), 0)
        else:
            effect(mn, op)
        i += 1
    return rows


def generate(elf, func, struct_name=None):
    img = Image(elf)
    sym, addr, size = img.func(func)
    cls, meth = demangle(sym)
    rows = trace(img, addr, size)
    names = fields_at(elf, struct_name or cls)

    print(f'// {cls}::{meth}  --  generated from SCUS_972.05 '
          f'@ 0x{addr:08x} ({size} bytes)')
    print(f'// {len(rows)} reader fields. Verify with verify.py before use.')
    print(f'void {cls}::{meth}(_zrdr* reader)\n{{')
    print('    if (!reader)\n        return;\n')
    cur = None
    for sc, key, helper, off, bit in rows:
        if key is None:     # key came from a register we could not follow
            print(f'    // TODO: {helper}(...) at an unresolved key -- '
                  f'read the disassembly for this one')
            continue
        if sc != cur:
            if cur is not None:
                print('    }\n')
            if sc:
                print(f'    if (_zrdr* {sc} = zrdr_findtag(reader, "{sc}"))\n    {{')
            cur = sc
        ind = '        ' if sc else '    '
        src = sc or 'reader'
        fld = names.get(off, (f'/*+0x{off:x}*/', ''))[0] if off is not None else '?'
        bits = f' mask |= 0x{bit:04x};' if bit else ''
        print(f'{ind}if ({helper}({src}, "{key}", &{fld}))'.ljust(66) + bits)
    if cur:
        print('    }')
    print('}')


if __name__ == '__main__':
    generate(*sys.argv[1:4])
