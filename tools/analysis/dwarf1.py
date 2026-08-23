"""DWARF v1 reader for SCUS_972.05's .debug section.

The Metrowerks MIPS compiler emitted plain DWARF 1 (confirmed: TAG_compile_unit
0x0011, AT_sibling 0x0012, AT_name 0x0038). That makes every class, struct,
union, enum and member offset in the game machine-readable ground truth --
exactly the type layouts reCOM currently hand-guesses from Ghidra.

usage: python dwarf1.py <SCUS_972.05> [NameFilter]
"""
import re, struct, sys, collections
from symbols import sections

# --- DWARF 1 constants (low nibble of an attribute code is its FORM) ---
FORM_ADDR, FORM_REF, FORM_BLOCK2, FORM_BLOCK4 = 1, 2, 3, 4
FORM_DATA2, FORM_DATA4, FORM_DATA8, FORM_STRING = 5, 6, 7, 8

TAG = {
    0x0001: 'array_type',      0x0002: 'class_type',    0x0004: 'enumeration_type',
    0x0005: 'formal_parameter', 0x0006: 'global_subroutine', 0x0007: 'global_variable',
    0x000a: 'label',           0x000b: 'lexical_block', 0x000c: 'local_variable',
    0x000d: 'member',          0x000f: 'pointer_type',  0x0010: 'reference_type',
    0x0011: 'compile_unit',    0x0013: 'structure_type', 0x0014: 'subroutine',
    0x0015: 'subroutine_type', 0x0016: 'typedef',       0x0017: 'union_type',
    0x0018: 'unspecified_parameters', 0x001c: 'inheritance',
    0x001d: 'inlined_subroutine', 0x001f: 'ptr_to_member_type',
    0x0021: 'subrange_type',   0x0023: 'enumerator',    0x002e: 'subprogram',
}
# Codes recovered empirically from this binary (116,691 records decode with
# zero breaks). The low nibble is the FORM, so each is name<<4 | form.
AT = {
    0x0012: 'sibling',       0x0023: 'location',   0x0038: 'name',
    0x0055: 'fund_type',     0x0072: 'user_def_type',
    0x0063: 'mod_fund_type', 0x0083: 'mod_u_d_type',
    0x00b6: 'byte_size',     0x00c5: 'bit_offset', 0x00d6: 'bit_size',
    0x0106: 'stmt_list',     0x0111: 'low_pc',     0x0121: 'high_pc',
    0x0258: 'producer',      0x00a3: 'subscr_data',
}
FT = {
    0x01: 'char', 0x02: 'signed char', 0x03: 'unsigned char', 0x04: 'short',
    0x05: 'short', 0x06: 'unsigned short', 0x07: 'int', 0x08: 'int',
    0x09: 'unsigned int', 0x0a: 'long', 0x0b: 'long', 0x0c: 'unsigned long',
    0x0d: 'void*', 0x0e: 'float', 0x0f: 'double', 0x10: 'long double',
    0x14: 'void', 0x15: 'bool', 0x8008: 'long long', 0x8108: 'unsigned long long',
}
MOD = {0x01: '*', 0x02: '&', 0x03: ' const', 0x04: ' volatile'}


class DIE:
    __slots__ = ('off', 'tag', 'at', 'children')
    def __init__(self, off, tag):
        self.off, self.tag, self.at, self.children = off, tag, {}, []
    def name(self):
        return self.at.get('name', '')
    def __repr__(self):
        return f'<{self.tag} {self.name()} @{self.off:#x}>'


def _attrs(blob, i, end):
    """Read attribute pairs until `end`. -> dict"""
    out = {}
    while i < end:
        code, = struct.unpack_from('<H', blob, i); i += 2
        form = code & 0xf
        if form == FORM_ADDR or form == FORM_REF or form == FORM_DATA4:
            v, = struct.unpack_from('<I', blob, i); i += 4
        elif form == FORM_DATA2:
            v, = struct.unpack_from('<H', blob, i); i += 2
        elif form == FORM_DATA8:
            v, = struct.unpack_from('<Q', blob, i); i += 8
        elif form == FORM_BLOCK2:
            n, = struct.unpack_from('<H', blob, i); i += 2
            v = blob[i:i + n]; i += n
        elif form == FORM_BLOCK4:
            n, = struct.unpack_from('<I', blob, i); i += 4
            v = blob[i:i + n]; i += n
        elif form == FORM_STRING:
            e = blob.index(b'\x00', i); v = blob[i:e].decode('latin-1'); i = e + 1
        else:
            break                                    # unknown form: stop this DIE
        out[AT.get(code, f'at_{code:#06x}')] = v
    return out


def parse(elf):
    """-> (list of top-level DIEs, {offset: DIE})"""
    d = open(elf, 'rb').read()
    S = sections(d)
    o, sz = S['.debug'][4], S['.debug'][5]
    blob = d[o:o + sz]

    flat = {}
    order = []
    i = 0
    while i + 4 <= len(blob):
        length, = struct.unpack_from('<I', blob, i)
        if length < 8:                                # padding entry
            i += max(length, 4); continue
        if i + length > len(blob):
            break
        tag, = struct.unpack_from('<H', blob, i + 4)
        die = DIE(i, TAG.get(tag, f'tag_{tag:#06x}'))
        try:
            die.at = _attrs(blob, i + 6, i + length)
        except (struct.error, ValueError):
            pass
        flat[i] = die; order.append(die)
        i += length

    # DWARF1 nests via AT_sibling: children are the DIEs between a node and
    # its sibling. Walk the flat list with a stack of pending sibling targets.
    roots, stack = [], []
    for die in order:
        while stack and die.off >= stack[-1][1]:
            stack.pop()
        (stack[-1][0].children if stack else roots).append(die)
        sib = die.at.get('sibling')
        if sib and sib > die.off:
            stack.append((die, sib))
    return roots, flat


def typename(die, flat, depth=0):
    """Render a member's type as C++ source text."""
    a = die.at
    if depth > 6:
        return '?'
    if 'fund_type' in a:
        return FT.get(a['fund_type'], f"ft_{a['fund_type']:#x}")
    if 'user_def_type' in a:
        t = flat.get(a['user_def_type'])
        return t.name() or f'<anon {t.tag}>' if t else '?'
    for key, base in (('mod_fund_type', 'f'), ('mod_u_d_type', 'u')):
        if key in a:
            b = a[key]
            mods, i = [], 0
            while i < len(b) - (2 if base == 'f' else 4):
                mods.append(MOD.get(b[i], '?')); i += 1
            if base == 'f':
                ft, = struct.unpack_from('<H', b, i)
                core = FT.get(ft, f'ft_{ft:#x}')
            else:
                ref, = struct.unpack_from('<I', b, i)
                t = flat.get(ref)
                core = (t.name() or f'<anon {t.tag}>') if t else '?'
            return core + ''.join(reversed(mods))
    return 'void'


OP_CONST, OP_ADD = 0x04, 0x07

def member_offset(die):
    """A member's AT_location is the block OP_CONST <u32 offset> OP_ADD."""
    loc = die.at.get('location')
    if (isinstance(loc, (bytes, bytearray)) and len(loc) >= 6
            and loc[0] == OP_CONST and loc[5] == OP_ADD):
        return struct.unpack_from('<I', loc, 1)[0]
    return None


def records(roots):
    """Yield every class/struct/union DIE anywhere in the tree."""
    stack = list(roots)
    while stack:
        d = stack.pop()
        if d.tag in ('class_type', 'structure_type', 'union_type'):
            yield d
        stack.extend(d.children)


def render(die, flat):
    kw = {'class_type': 'class', 'structure_type': 'struct',
          'union_type': 'union'}[die.tag]
    size = die.at.get('byte_size')
    out = [f'{kw} {die.name() or "<anon>"}'
           + (f'  // 0x{size:x} ({size}) bytes' if size else '') + ' {']
    for c in die.children:
        if c.tag == 'inheritance':
            out.append(f'    : public {typename(c, flat)}')
        elif c.tag == 'member':
            off = member_offset(c)
            pos = f'0x{off:04x}' if off is not None else '  ?  '
            bits = f':{c.at["bit_size"]}' if 'bit_size' in c.at else ''
            out.append(f'    /* {pos} */ {typename(c, flat)} {c.name()}{bits};')
    out.append('};')
    return '\n'.join(out)


def demo():
    # attribute decoding: AT_name(string), AT_sibling(ref), AT_byte_size(data4)
    blob = (struct.pack('<H', 0x0038) + b'Foo\x00'
            + struct.pack('<HI', 0x0012, 0x74)
            + struct.pack('<HI', 0x00b6, 16))
    a = _attrs(blob, 0, len(blob))
    assert a == {'name': 'Foo', 'sibling': 0x74, 'byte_size': 16}, a
    # a member location block is OP_CONST(0x10) + u32 offset
    m = DIE(0, 'member')
    m.at['location'] = bytes([OP_CONST]) + struct.pack('<I', 12) + bytes([OP_ADD])
    assert member_offset(m) == 12
    m.at['location'] = bytes([0x03]) + struct.pack('<I', 12)   # OP_ADDR: a global
    assert member_offset(m) is None
    assert FT[0x0e] == 'float' and MOD[0x01] == '*'
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        demo(); sys.exit()
    roots, flat = parse(sys.argv[1])
    want = sys.argv[2] if len(sys.argv) > 2 else None
    seen, n = set(), 0
    for d in records(roots):
        nm = d.name()
        if not nm or nm in seen:
            continue
        if want and want.lower() not in nm.lower():
            continue
        seen.add(nm); n += 1
        if want:
            print(render(d, flat), '\n')
    if not want:
        print(f'named class/struct/union types: {n}')
