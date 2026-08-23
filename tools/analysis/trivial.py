"""Classify and emit the small leaf functions of SCUS_972.05.

30% of the game's 9,703 functions are 64 bytes or less -- accessors, setters,
constant returns, thunks. They have no control flow, so each reduces to a
template match on two or three instructions rather than real decompilation.

The delay slot after `jr $ra` executes before the return, so the effective
body is everything before the jr, plus that one trailing instruction.

usage: python trivial.py <SCUS_972.05> [--emit]
"""
import collections, re, struct, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN
from disasm import Image
from symbols import demangle

MD = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)

# load mnemonic -> (C type hint, is_float)
LOADS = {'lw': ('s32', 0), 'lwu': ('u32', 0), 'lbu': ('u8', 0), 'lb': ('s8', 0),
         'lhu': ('u16', 0), 'lh': ('s16', 0), 'ld': ('s64', 0),
         'lwc1': ('f32', 1)}
STORES = {'sw': 's32', 'sb': 'u8', 'sh': 'u16', 'sd': 's64', 'swc1': 'f32'}
MEM = re.compile(r'^(\$\w+), (-?(?:0x)?[0-9a-fA-F]+)?\((\$\w+)\)$')


def body(img, addr, size):
    """-> list of (mnemonic, op_str) that actually execute, or None."""
    code = img.read(addr, size)
    ins = []
    for i in range(0, len(code) - 3, 4):
        got = list(MD.disasm(code[i:i + 4], addr + i))
        if not got:
            return None                       # unknown opcode: don't guess
        ins.append((got[0].mnemonic, got[0].op_str))
    jr = next((i for i, (m, o) in enumerate(ins) if m == 'jr' and o == '$ra'), None)
    if jr is None or jr + 1 >= len(ins):
        return None                           # no return, or no delay slot
    out = ins[:jr] + [ins[jr + 1]]
    return [(m, o) for m, o in out if m != 'nop']


def classify(b):
    """-> (kind, detail) for a template match, else ('other', None)."""
    if not b:
        return 'empty', None
    if len(b) == 1:
        m, o = b[0]
        mm = MEM.match(o)
        if m in LOADS and mm and mm.group(3) == '$a0' and mm.group(1) in ('$v0', '$f0'):
            return 'getter', (int(mm.group(2) or '0', 0), LOADS[m][0])
        if m in STORES and mm and mm.group(3) == '$a0':
            return 'setter', (int(mm.group(2) or '0', 0), STORES[m])
        if m == 'move' and o == '$v0, $zero':
            return 'ret_const', 0
        if m == 'move' and o == '$v0, $a0':
            return 'ret_this', None
        mm2 = re.match(r'^\$v0, \$zero, (-?(?:0x)?[0-9a-fA-F]+)$', o)
        if m in ('addiu', 'ori', 'li') and mm2:
            return 'ret_const', int(mm2.group(1), 0)
        mm3 = re.match(r'^\$v0, \$a0, (-?(?:0x)?[0-9a-fA-F]+)$', o)
        if m == 'addiu' and mm3:
            return 'ret_field_addr', int(mm3.group(1), 0)
        # a $gp-relative access is a global, not a member
        if m in LOADS and mm and mm.group(3) == '$gp':
            return 'global_get', (int(mm.group(2) or '0', 0), LOADS[m][0])
        if m in STORES and mm and mm.group(3) == '$gp':
            return 'global_set', (int(mm.group(2) or '0', 0), STORES[m])

    # PS2 kernel syscall thunk -- SCE runtime, not game code
    if len(b) == 2 and b[1][0] == 'syscall' and b[0][0] == 'addiu':
        n = re.match(r'^\$v1, \$zero, (-?(?:0x)?[0-9a-fA-F]+)$', b[0][1])
        return 'syscall_stub', int(n.group(1), 0) if n else None

    # constructor that zeroes members then returns this
    zeros, ret_this, ok = [], False, True
    for m, o in b:
        mm = MEM.match(o)
        if m in STORES and mm and mm.group(3) == '$a0' and mm.group(1) == '$zero':
            zeros.append(int(mm.group(2) or '0', 0))
        elif m == 'move' and o == '$v0, $a0':
            ret_this = True
        else:
            ok = False
            break
    if ok and zeros and ret_this:
        return 'ctor_zero', sorted(zeros)

    # return this->a->b  (two chained loads)
    if len(b) == 2 and b[0][0] in LOADS and b[1][0] in LOADS:
        m0, m1 = MEM.match(b[0][1]), MEM.match(b[1][1])
        if (m0 and m1 and m0.group(3) == '$a0' and m1.group(3) == m0.group(1)
                and m1.group(1) in ('$v0', '$f0')):
            return 'getter_chain', (int(m0.group(2) or '0', 0),
                                    int(m1.group(2) or '0', 0), LOADS[b[1][0]][0])
    return 'other', None


def fieldmap(elf):
    """-> {class: {offset: name}} from DWARF, for naming accessor targets."""
    from dwarf1 import parse, records, member_offset
    roots, _flat = parse(elf)
    out = {}
    for d in records(roots):
        n = d.name()
        if not n:
            continue
        mem = {member_offset(c): c.name()
               for c in d.children if c.tag == 'member' and member_offset(c) is not None}
        if mem and len(mem) > len(out.get(n, {})):
            out[n] = mem
    return out


def emit(cls, meth, kind, detail, fields):
    def fname(off):
        return (fields.get(cls) or {}).get(off, f'/*+0x{off:x}*/')
    q = f'{cls}::{meth}' if cls else meth
    if kind == 'empty':
        return f'void {q}() {{ }}'
    if kind == 'getter':
        off, ty = detail
        return f'{ty} {q}() const {{ return {fname(off)}; }}'
    if kind == 'setter':
        off, ty = detail
        return f'void {q}({ty} v) {{ {fname(off)} = v; }}'
    if kind == 'ret_const':
        return f'int {q}() {{ return {detail}; }}'
    if kind == 'ret_this':
        return f'{cls}* {q}() {{ return this; }}'
    if kind == 'ret_field_addr':
        return f'void* {q}() {{ return &{fname(detail)}; }}'
    if kind == 'ctor_zero':
        body = ' '.join(f'{fname(o)} = 0;' for o in detail)
        return f'{q}() {{ {body} }}'
    if kind == 'getter_chain':
        o1, o2, ty = detail
        return f'{ty} {q}() const {{ return {fname(o1)}->/*+0x{o2:x}*/; }}'
    if kind == 'global_get':
        off, ty = detail
        return f'{ty} {q}() {{ return /*gp{off:+#x}*/; }}'
    if kind == 'global_set':
        off, ty = detail
        return f'void {q}({ty} v) {{ /*gp{off:+#x}*/ = v; }}'
    return None


def main(elf, do_emit=False):
    img = Image(elf)
    fields = fieldmap(elf) if do_emit else {}
    kinds = collections.Counter()
    out = []
    for sym, addr, size in img.funcs:
        if not 0 < size <= 64:
            continue
        b = body(img, addr, size)
        if b is None:
            kinds['undecodable'] += 1
            continue
        kind, detail = classify(b)
        kinds[kind] += 1
        if do_emit and kind != 'other':
            cls, meth = demangle(sym)
            line = emit(cls, meth, kind, detail, fields)
            if line:
                out.append((addr, line))
    tot = sum(kinds.values())
    matched = tot - kinds['other'] - kinds['undecodable'] - kinds['syscall_stub']
    print(f'functions <=64 bytes: {tot}')
    for k, n in kinds.most_common():
        print(f'   {k:16s} {n:5d}  {100 * n / tot:5.1f}%')
    game = tot - kinds['syscall_stub']
    print(f'\nsyscall stubs (SCE runtime, not game code): {kinds["syscall_stub"]}')
    print(f'template-matched: {matched} of {game} game functions '
          f'({100 * matched / game:.0f}%)')
    if do_emit:
        out.sort()
        with open('decomp/trivial.cpp', 'w') as f:
            f.write('// Small leaf functions of SCUS_972.05, template-matched.\n'
                    '// Generated by trivial.py -- signatures are inferred from the\n'
                    '// access width, so return/param types need a human pass.\n\n')
            for a, line in out:
                f.write(f'/* 0x{a:08x} */ {line}\n')
        print(f'wrote decomp/trivial.cpp ({len(out)} functions)')


def demo():
    assert classify([('lw', '$v0, 0x10($a0)')]) == ('getter', (16, 's32'))
    assert classify([('lwc1', '$f0, 4($a0)')]) == ('getter', (4, 'f32'))
    assert classify([('sw', '$a1, 8($a0)')]) == ('setter', (8, 's32'))
    assert classify([('move', '$v0, $zero')]) == ('ret_const', 0)
    assert classify([('addiu', '$v0, $zero, 1')]) == ('ret_const', 1)
    assert classify([]) == ('empty', None)
    assert classify([('jal', '0x1234')])[0] == 'other'
    # a load through a register other than $a0 is not a this-> accessor
    assert classify([('lw', '$v0, 0x10($s1)')])[0] == 'other'
    assert classify([('addiu', '$v1, $zero, 0x80'),
                     ('syscall', '')]) == ('syscall_stub', 0x80)
    assert classify([('sw', '$zero, ($a0)'), ('move', '$v0, $a0'),
                     ('sw', '$zero, 4($a0)')]) == ('ctor_zero', [0, 4])
    assert classify([('lw', '$v1, ($a0)'),
                     ('lw', '$v0, 0x88($v1)')]) == ('getter_chain', (0, 0x88, 's32'))
    assert classify([('lw', '$v0, -0x6524($gp)')])[0] == 'global_get'
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        demo()
    else:
        main(sys.argv[1], '--emit' in sys.argv)
