"""Lift R5900 machine code to compilable C++, one instruction at a time.

Hand-decompiling 7,275 functions is not reachable. But difftest.py can decide
correctness automatically, so the loop does not need a human in it: emit a
faithful transliteration, let the verifier judge it, and keep what passes.

The output is register-machine C++ with gotos, not idiomatic code -- the same
shape Ghidra or Hex-Rays produce as a first pass. Its value is that it is
*verified*, so it is a correct starting point for a human rewrite instead of
a guess.

Delay slots are the crux: the instruction after a branch executes before the
jump, so the branch condition is captured into a temporary using the
pre-delay-slot register values, then the delay slot runs, then the jump.

usage: python lift.py <SCUS_972.05> <Function> [objsize]
"""
import re, struct, sys
from disasm import Image
from emu import Machine, Unsupported, REGS, decode_mmi
from symbols import demangle

RN = {n: i for i, n in enumerate(REGS)}
STACK_TOP = 0x01f00000
OBJ_ADDR = 0x00c00000

PROLOGUE = '''// Lifted from SCUS_972.05 @ %s by lift.py -- verified by difftest.py.
// Register-machine transliteration, not idiomatic C++: correct first, readable
// second. Rewrite by hand using this as the reference for what the ROM does.
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <cstdlib>
typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32; typedef int64_t s64;
static unsigned char* g_obj; static unsigned g_objn;
static unsigned char g_stk[2048];
// Anything outside the object and the stack lives in an exact sparse table
// that reads as zero, matching the interpreter. A scratch buffer indexed
// modulo its size would alias addresses the interpreter keeps distinct.
//
// Paged, NOT byte-keyed: a map with one node per byte costs ~50 bytes of
// overhead per address, so a function touching a megabyte allocated over a
// gigabyte of driver memory. 4 KB pages make that ~1/1000th.
// The interpreter stops a runaway function at its step limit; lifted C++ has
// no such brake, so a mis-lifted branch spins forever and allocates pages
// until the machine dies. These budgets turn that into a clean exit(97),
// which difftest records as a failure instead of taking the box down.
static const unsigned long long OP_BUDGET = 20000000ull;   // memory ops
static const size_t PAGE_BUDGET = 16384;                   // 64 MB of pages
static unsigned long long g_ops;
static std::unordered_map<u32, unsigned char*> g_pages;

static inline unsigned char* MP(u64 a) {
    a &= 0xffffffffu;
    if (a >= %#xu && a < %#xu + g_objn) return g_obj + (a - %#xu);
    if (a >= %#xu - sizeof(g_stk) && a < %#xu) return g_stk + (a - (%#xu - sizeof(g_stk)));
    if (++g_ops > OP_BUDGET) std::_Exit(97);   // runaway: bounded, not OOM
    u32 key = (u32)a >> 12;
    unsigned char*& pg = g_pages[key];
    if (!pg) {
        if (g_pages.size() > PAGE_BUDGET) std::_Exit(97);
        pg = new unsigned char[4096]();
    }
    return pg + (a & 0xfff);
}
static inline void far_reset() {           // release, don't just clear
    for (auto& kv : g_pages) delete[] kv.second;
    std::unordered_map<u32, unsigned char*>().swap(g_pages);
}
// Resolve every byte separately. MP() hands back storage for ONE address --
// in the sparse map each byte is its own node, so indexing p[1..3] off a
// single lookup reads adjacent hash-table memory instead of the next address.
static inline u64 LD(u64 a, int n, int sg) {
    u64 v = 0;
    for (int i = 0; i < n; i++) v |= (u64)*MP(a + i) << (8*i);
    if (sg && (v >> (8*n-1)) & 1) v |= ~((u64)0) << (8*n);
    return v;
}
static inline void ST(u64 a, int n, u64 v) {
    for (int i = 0; i < n; i++) *MP(a + i) = (unsigned char)(v >> (8*i));
}
static inline float B2F(u32 b){ float f; std::memcpy(&f,&b,4); return f; }
static inline u32 F2B(float f){ u32 b; std::memcpy(&b,&f,4); return b; }
static inline u32 FSAT(double d){            // R5900 has no Inf: saturate
    const double M = 3.40282346638528860e+38;
    if (d > M) d = M; if (d < -M) d = -M;
    return F2B((float)d);
}
// Machine state is file-scope so a lifted `jal` is just a C++ call: the
// callee sees the same registers, exactly as on hardware.
static u64 r[32], rq[32], hi, lo, hi1, lo1; static u32 f[32];
static const u64 ZERO = 0;
static bool fcc, cond;
'''

LOADS = {'lb': (1, 1), 'lbu': (1, 0), 'lh': (2, 1), 'lhu': (2, 0),
         'lw': (4, 1), 'lwu': (4, 0), 'ld': (8, 0)}
STORES = {'sb': 1, 'sh': 2, 'sw': 4, 'sd': 8}


def R(n):
    return 'ZERO' if n == '$zero' else f'r[{RN[n]}]'


def W(n, expr):
    """Assignment that silently drops writes to $zero, as the hardware does."""
    return '' if n == '$zero' else f'r[{RN[n]}] = (u64)({expr});'


def F(n):
    return f'f[{int(n[2:])}]'


def mem(addr):
    o, b = (addr.split('(') + [''])[:2]
    b = b.rstrip(')')
    off = int(o, 0) if o.strip() else 0
    return f'({R(b)} + {off})'


class Unliftable(Exception):
    pass


def lift_one(mn, ops, pc, labels):
    """-> C++ statement for one non-branch instruction."""
    p = [x.strip() for x in ops.split(',')] if ops else []
    # `break 0, 7` is the divide-by-zero trap Metrowerks emits after every
    # div; it sits behind a branch and is unreachable for valid operands.
    if mn in ('nop', 'ehb', 'ssnop', 'sync', 'cache',
              'cop0nop', 'ei', 'di', 'mtc0', 'break', 'teq', 'tne'):
        return ';'
    if mn == 'mfc0':
        return W(p[0], '0')
    if mn in ('lq', 'sq'):
        a = mem(p[1])
        if mn == 'sq':
            return f'ST(({a}) & ~15ull, 8, {R(p[0])}); ST((({a}) & ~15ull)+8, 8, rq[{RN[p[0]]}]);'
        return (f'{W(p[0], f"LD(({a}) & ~15ull, 8, 0)")} '
                f'rq[{RN[p[0]]}] = LD((({a}) & ~15ull)+8, 8, 0);')
    if mn in LOADS:
        n, sg = LOADS[mn]
        return W(p[0], f'LD({mem(p[1])}, {n}, {sg})')
    if mn in STORES:
        return f'ST({mem(p[1])}, {STORES[mn]}, {R(p[0])});'
    if mn == 'lwc1':
        return f'{F(p[0])} = (u32)LD({mem(p[1])}, 4, 0);'
    if mn == 'swc1':
        return f'ST({mem(p[1])}, 4, {F(p[0])});'
    # FPU
    if mn in ('add.s', 'sub.s', 'mul.s'):
        op = {'add.s': '+', 'sub.s': '-', 'mul.s': '*'}[mn]
        return f'{F(p[0])} = FSAT((double)B2F({F(p[1])}) {op} (double)B2F({F(p[2])}));'
    if mn == 'div.s':
        return (f'{F(p[0])} = (B2F({F(p[2])}) == 0.0f) '
                f'? (0x7f7fffffu | ((({F(p[1])}) ^ ({F(p[2])})) & 0x80000000u)) '
                f': FSAT((double)B2F({F(p[1])}) / (double)B2F({F(p[2])}));')
    if mn == 'abs.s':
        return f'{F(p[0])} = {F(p[1])} & 0x7fffffffu;'
    if mn == 'neg.s':
        return f'{F(p[0])} = {F(p[1])} ^ 0x80000000u;'
    if mn == 'mov.s':
        return f'{F(p[0])} = {F(p[1])};'
    if mn == 'cvt.s.w':
        return f'{F(p[0])} = F2B((float)(s32){F(p[1])});'
    if mn in ('cvt.w.s', 'trunc.w.s'):
        return f'{F(p[0])} = (u32)(s32)B2F({F(p[1])});'
    if mn == 'mtc1':
        return f'{F(p[1])} = (u32){R(p[0])};'
    if mn == 'mfc1':
        return W(p[0], f'(s64)(s32){F(p[1])}')
    m = re.match(r'c\.(\w+)\.s', mn)
    if m:
        cmp = {'eq': '==', 'ueq': '==', 'oeq': '==', 'lt': '<', 'ult': '<',
               'olt': '<', 'le': '<=', 'ule': '<=', 'ole': '<='}.get(m.group(1))
        if cmp:
            return f'fcc = (B2F({F(p[0])}) {cmp} B2F({F(p[1])}));'
        raise Unliftable(mn)
    # integer
    if mn == 'move':
        return W(p[0], R(p[1]))
    if mn == 'li':
        return W(p[0], f'{int(p[1], 0)}ll')
    if mn in ('addiu', 'addi', 'daddiu', 'daddi'):
        return W(p[0], f'{R(p[1])} + ({int(p[2], 0)}ll)')
    if mn in ('addu', 'add', 'daddu', 'dadd'):
        return W(p[0], f'{R(p[1])} + {R(p[2])}')
    if mn in ('subu', 'sub', 'dsubu', 'dsub'):
        return W(p[0], f'{R(p[1])} - {R(p[2])}')
    if mn == 'negu':
        return W(p[0], f'-{R(p[1])}')
    if mn == 'not':
        return W(p[0], f'~{R(p[1])}')
    if mn == 'sltiu':
        return W(p[0], f'((u32){R(p[1])} < (u32){int(p[2], 0) & 0xffffffff}u) ? 1 : 0')
    if mn == 'slti':
        return W(p[0], f'((s32){R(p[1])} < (s32){int(p[2], 0)}) ? 1 : 0')
    if mn == 'sltu':
        return W(p[0], f'((u32){R(p[1])} < (u32){R(p[2])}) ? 1 : 0')
    if mn == 'slt':
        return W(p[0], f'((s32){R(p[1])} < (s32){R(p[2])}) ? 1 : 0')
    if mn == 'andi':
        return W(p[0], f'{R(p[1])} & {int(p[2], 0)}ull')
    if mn == 'ori':
        return W(p[0], f'{R(p[1])} | {int(p[2], 0)}ull')
    if mn == 'xori':
        return W(p[0], f'{R(p[1])} ^ {int(p[2], 0)}ull')
    if mn in ('and', 'or', 'xor'):
        return W(p[0], f'{R(p[1])} {{"and":"&","or":"|","xor":"^"}}'.replace(
            '{"and":"&","or":"|","xor":"^"}', {'and': '&', 'or': '|', 'xor': '^'}[mn])
            + f' {R(p[2])}')
    if mn == 'nor':
        return W(p[0], f'~({R(p[1])} | {R(p[2])})')
    if mn == 'lui':
        return W(p[0], f'(u32)({int(p[1], 0)}u << 16)')
    if mn in ('sll', 'srl', 'sra'):
        sh = int(p[2], 0) & 31
        if mn == 'sll':
            e = f'(s32)((u32){R(p[1])} << {sh})'
        elif mn == 'srl':
            e = f'(s32)((u32){R(p[1])} >> {sh})'
        else:
            e = f'((s32){R(p[1])} >> {sh})'
        return W(p[0], f'(s64){e}')
    if mn in ('sllv', 'srlv', 'srav'):
        sh = f'({R(p[2])} & 31)'
        if mn == 'sllv':
            e = f'(s32)((u32){R(p[1])} << {sh})'
        elif mn == 'srlv':
            e = f'(s32)((u32){R(p[1])} >> {sh})'
        else:
            e = f'((s32){R(p[1])} >> {sh})'
        return W(p[0], f'(s64){e}')
    if mn in ('dsllv', 'dsrlv', 'dsrav'):
        sh = f'({R(p[2])} & 63)'
        if mn == 'dsllv':
            return W(p[0], f'{R(p[1])} << {sh}')
        if mn == 'dsrlv':
            return W(p[0], f'{R(p[1])} >> {sh}')
        return W(p[0], f'(u64)((s64){R(p[1])} >> {sh})')
    if mn in ('dsll', 'dsll32', 'dsrl', 'dsrl32', 'dsra', 'dsra32'):
        sh = int(p[2], 0) + (32 if mn.endswith('32') else 0)
        if mn.startswith('dsll'):
            return W(p[0], f'{R(p[1])} << {sh}')
        if mn.startswith('dsrl'):
            return W(p[0], f'{R(p[1])} >> {sh}')
        return W(p[0], f'(u64)((s64){R(p[1])} >> {sh})')
    if mn in ('mult', 'multu'):
        c = 's64)(s32' if mn == 'mult' else 'u64)(u32'
        return (f'{{ {"s64" if mn == "mult" else "u64"} _t = ({c}){R(p[0])} * '
                f'({c}){R(p[1])}; lo = (s64)(s32)_t; hi = (s64)(s32)(_t >> 32); }}')
    if mn == 'mul':
        return W(p[0], f'(s64)(s32)((u32){R(p[1])} * (u32){R(p[2])})')
    if mn in ('div', 'divu'):
        if mn == 'div':
            return (f'{{ s32 _a=(s32){R(p[0])}, _b=(s32){R(p[1])}; if(_b){{ '
                    f'lo=(s64)(_a/_b); hi=(s64)(_a%_b);}} }}')
        return (f'{{ u32 _a=(u32){R(p[0])}, _b=(u32){R(p[1])}; if(_b){{ '
                f'lo=(s64)(s32)(_a/_b); hi=(s64)(s32)(_a%_b);}} }}')
    if mn in ('mult3', 'multu3', 'mult1', 'multu1'):
        acc = ('lo1', 'hi1') if mn.endswith('1') else ('lo', 'hi')
        cast = 's64)(s32' if mn in ('mult3', 'mult1') else 'u64)(u32'
        return (f'{{ {"s64" if cast.startswith("s") else "u64"} _t = '
                f'({cast}){R(p[1])} * ({cast}){R(p[2])}; '
                f'{acc[0]} = (s64)(s32)_t; {acc[1]} = (s64)(s32)(_t >> 32); '
                f'{W(p[0], acc[0])} }}')
    if mn in ('div1', 'divu1'):
        t = 's32' if mn == 'div1' else 'u32'
        return (f'{{ {t} _a=({t}){R(p[0])}, _b=({t}){R(p[1])}; if(_b){{ '
                f'lo1=(s64)(s32)(_a/_b); hi1=(s64)(s32)(_a%_b);}} }}')
    if mn == 'mfhi1':
        return W(p[0], 'hi1')
    if mn == 'mflo1':
        return W(p[0], 'lo1')
    if mn == 'mthi1':
        return 'hi1 = ' + R(p[0]) + ';'
    if mn == 'mtlo1':
        return 'lo1 = ' + R(p[0]) + ';'
    if mn == 'pcpyld':
        return f'rq[{RN[p[0]]}] = {R(p[1])}; {W(p[0], R(p[2]))}'
    if mn == 'mfhi':
        return W(p[0], 'hi')
    if mn == 'mflo':
        return W(p[0], 'lo')
    if mn in ('movn', 'movz'):
        c = '!=' if mn == 'movn' else '=='
        return f'if ({R(p[2])} {c} 0) {{ {W(p[0], R(p[1]))} }}'
    raise Unliftable(f'{mn} {ops}')


COND_C = {
    'beqz': '{0} == 0', 'bnez': '{0} != 0',
    'beq': '{0} == {1}', 'bne': '{0} != {1}',
    'blez': '(s64){0} <= 0', 'bgtz': '(s64){0} > 0',
    'bltz': '(s64){0} < 0', 'bgez': '(s64){0} >= 0',
}


def lift_body(m, img, addr, size, callees):
    """Emit one function's body. Records jal targets in `callees`."""
    ins = {}
    for pc in range(addr, addr + size, 4):
        ins[pc] = m.ins(pc)

    labels = set()
    for pc, (mn, ops) in ins.items():
        if (mn in COND_C or mn.rstrip('l') in COND_C or
                mn in ('b', 'j', 'bc1t', 'bc1f', 'bc1tl', 'bc1fl')):
            t = None
            if ops.startswith('0x'):
                t = int(ops, 0)
            else:
                last = ops.split(',')[-1].strip()
                if last.startswith('0x'):
                    t = int(last, 0)
            if t is not None and addr <= t < addr + size:
                labels.add(t)

    body = []
    pc = addr
    while pc < addr + size:
        mn, ops = ins[pc]
        if pc in labels:
            body.append(f'L_{pc:x}:;')
        p = [x.strip() for x in ops.split(',')] if ops else []
        nxt = ins.get(pc + 4)

        if mn == 'jr' and p and p[0] == '$ra':
            if nxt:
                body.append('  ' + lift_one(*nxt, pc + 4, labels))
            body.append('  goto L_done;')
            pc += 8
            continue
        if mn in ('jal', 'bal'):
            t = int(ops, 0)
            if t not in img.byaddr:
                raise Unliftable(f'{mn} to unknown target {t:#x}')
            callees.add(t)
            if nxt:                      # delay slot runs before the call
                body.append('  ' + lift_one(*nxt, pc + 4, labels))
            body.append(f'  fn_{t:x}();')
            pc += 8
            continue
        if mn == 'j' and ops.startswith('0x') and int(ops, 0) not in labels:
            t = int(ops, 0)              # tail call: run it, then return
            if t not in img.byaddr:
                raise Unliftable(f'tail call to unknown target {t:#x}')
            callees.add(t)
            if nxt:
                body.append('  ' + lift_one(*nxt, pc + 4, labels))
            body.append(f'  fn_{t:x}();')
            body.append('  goto L_done;')
            pc += 8
            continue
        if mn in ('jalr', 'jr'):
            raise Unliftable(f'{mn} (indirect jump)')
        base = mn[:-1] if (mn.endswith('l') and mn[:-1] in COND_C) else mn
        if base in COND_C or mn in ('bc1t', 'bc1f', 'bc1tl', 'bc1fl'):
            likely = mn != base or mn.endswith('l')
            t = int(p[-1], 0)
            if t not in labels:
                raise Unliftable('branch out of function')
            if mn.startswith('bc1'):
                cond = 'fcc' if mn.startswith('bc1t') else '!fcc'
            else:
                cond = COND_C[base].format(R(p[0]),
                                           R(p[1]) if len(p) == 3 else '0')
            body.append(f'  cond = ({cond});')          # captured pre-delay-slot
            if nxt:
                stmt = lift_one(*nxt, pc + 4, labels)
                body.append(f'  if (cond) {{ {stmt} }}' if likely else '  ' + stmt)
            body.append(f'  if (cond) goto L_{t:x};')
            pc += 8
            continue
        if mn == 'b':
            t = int(ops, 0)
            if t not in labels:
                raise Unliftable('branch out of function')
            if nxt:
                body.append('  ' + lift_one(*nxt, pc + 4, labels))
            body.append(f'  goto L_{t:x};')
            pc += 8
            continue
        body.append('  ' + lift_one(mn, ops, pc, labels))
        pc += 4

    return body


MAX_FUNCS = 48          # a runaway call graph is not worth lifting


def lift(elf, func, objsize=0):
    img = Image(elf)
    m = Machine(img)
    sym, addr, size = img.func(func)
    cls, meth = demangle(sym)

    # Lift the entry point and everything it calls, transitively.
    bodies, todo, seen = {}, [(addr, size)], set()
    while todo:
        a, sz = todo.pop()
        if a in seen:
            continue
        seen.add(a)
        if len(seen) > MAX_FUNCS:
            raise Unliftable(f'call graph exceeds {MAX_FUNCS} functions')
        callees = set()
        bodies[a] = lift_body(m, img, a, sz, callees)
        for t in callees:
            if t not in seen:
                todo.append((t, img.byaddr[t][1]))

    name = f'{cls}::{meth}' if cls else meth
    out = [PROLOGUE % (f'0x{addr:08x}  ({name}, {size} bytes, '
                       f'{len(bodies)} function(s) lifted)',
                       OBJ_ADDR, OBJ_ADDR, OBJ_ADDR,
                       STACK_TOP, STACK_TOP, STACK_TOP)]
    for a in bodies:                                   # forward declarations
        out.append(f'static void fn_{a:x}(void);')
    for a, body in bodies.items():
        out.append(f'\nstatic void fn_{a:x}(void) {{')
        out.extend(body)
        out.append('L_done:; return;')
        out.append('}')
    out.append('\nextern "C" unsigned test_entry(unsigned char* obj, unsigned arg) {')
    out.append(f'  g_obj = obj; g_objn = {objsize or 1};')
    out.append('  std::memset(g_stk, 0, sizeof(g_stk));')
    out.append('  far_reset(); g_ops = 0;')
    out.append('  std::memset(r, 0, sizeof(r)); std::memset(rq, 0, sizeof(rq));')
    out.append('  std::memset(f, 0, sizeof(f)); hi = lo = hi1 = lo1 = 0; fcc = cond = false;')
    out.append(f'  r[{RN["$a0"]}] = {OBJ_ADDR}ull; r[{RN["$a1"]}] = arg;')
    out.append(f'  r[{RN["$a2"]}] = arg; r[{RN["$a3"]}] = arg;')
    out.append(f'  r[{RN["$sp"]}] = {STACK_TOP}ull;')
    out.append(f'  r[{RN["$gp"]}] = {m.gp}ull;')
    out.append('  f[12] = F2B((float)arg);')
    out.append(f'  fn_{addr:x}();')
    out.append(f'  return (unsigned)(u32)r[{RN["$v0"]}];')
    out.append('}')
    return '\n'.join(out)


if __name__ == '__main__':
    print(lift(sys.argv[1], sys.argv[2],
               int(sys.argv[3]) if len(sys.argv) > 3 else 0))
