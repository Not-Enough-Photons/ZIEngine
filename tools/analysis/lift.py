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
       python lift.py            # jump-table recovery self-check
"""
import os, re, struct, sys
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
#include <cstdio>
#include <cmath>
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
// The interpreter serves reads of mapped addresses from the real ELF, so the
// lifted code must too -- otherwise every global and constant table reads as
// zero here and as real data there. Pages are copy-on-write: a page inside
// the image is seeded from the file, writes then stay local, which is exactly
// the interpreter's overlay-over-image behaviour.
static const char* IMG_PATH = "%s";
static const u32 IMG_BASE = %#xu, IMG_SIZE = %#xu, IMG_OFF = %#xu;
static unsigned char* g_img;
static void img_load() {
    if (g_img) return;
    g_img = new unsigned char[IMG_SIZE]();
    if (FILE* fp = std::fopen(IMG_PATH, "rb")) {
        std::fseek(fp, (long)IMG_OFF, SEEK_SET);
        size_t rd = std::fread(g_img, 1, IMG_SIZE, fp);
        (void)rd;
        std::fclose(fp);
    }
}
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
        u32 pa = key << 12;                       // seed from the image
        if (pa + 4096 > IMG_BASE && pa < IMG_BASE + IMG_SIZE) {
            img_load();
            for (u32 i = 0; i < 4096; i++) {
                u32 abs_ = pa + i;
                if (abs_ >= IMG_BASE && abs_ < IMG_BASE + IMG_SIZE)
                    pg[i] = g_img[abs_ - IMG_BASE];
            }
        }

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
static inline u64 SX32(u64 v){ return (u64)(s64)(s32)(u32)v; }
// Unaligned loads merge a partial word into the register instead of
// replacing it. Little-endian: LWL takes bytes from the aligned word start
// up to the address into the high end; LWR takes the address to the word
// end into the low end.
static inline void SWL(u64 v, u64 a, int w) {
    for (int i = 0; i <= (int)(a & (u64)(w - 1)); i++)
        *MP(a - i) = (unsigned char)(v >> (8 * (w - 1 - i)));
}
static inline void SWR(u64 v, u64 a, int w) {
    for (int i = 0; i < w - (int)(a & (u64)(w - 1)); i++)
        *MP(a + i) = (unsigned char)(v >> (8 * i));
}
static inline u64 LWL(u64 old, u64 a, int w) {
    for (int i = 0; i <= (int)(a & (u64)(w - 1)); i++) {
        int sh = 8 * (w - 1 - i);
        old = (old & ~(0xffull << sh)) | ((u64)*MP(a - i) << sh);
    }
    return old;
}
static inline u64 LWR(u64 old, u64 a, int w) {
    for (int i = 0; i < w - (int)(a & (u64)(w - 1)); i++) {
        int sh = 8 * i;
        old = (old & ~(0xffull << sh)) | ((u64)*MP(a + i) << sh);
    }
    return old;
}
static inline u32 F2B(float f){ u32 b; std::memcpy(&b,&f,4); return b; }
// The EE FPU is not IEEE754. Inputs are denormals-are-zero and the
// exponent-255 patterns it can never produce read as +/-FLT_MAX; results
// round toward zero (chop, not nearest) and flush denormals to zero.
// Bit moves (mov.s/abs.s/neg.s/lwc1/swc1) bypass this and use raw f[] values.
static const float EE_FMAX = 3.40282347e+38f;
static inline float B2F(u32 b){
    u32 e = b & 0x7f800000u;
    if (e == 0)          return (b & 0x80000000u) ? -0.0f : 0.0f;      // DAZ
    if (e == 0x7f800000u) return (b & 0x80000000u) ? -EE_FMAX : EE_FMAX;
    float f; std::memcpy(&f,&b,4); return f;
}
static inline u32 FSAT(double d){
    const double M = 3.40282346638528860e+38;
    if (d >  M) return 0x7f7fffffu;
    if (d < -M) return 0xff7fffffu;
    float y = (float)d;
    if (std::fabs((double)y) > std::fabs(d))       // rounded away from zero
        y = std::nextafterf(y, 0.0f);              // chop
    u32 b = F2B(y);
    if (!(b & 0x7f800000u)) b &= 0x80000000u;      // FTZ
    return b;
}
// Machine state is file-scope so a lifted `jal` is just a C++ call: the
// callee sees the same registers, exactly as on hardware.
static u64 r[32], rq[32], hi, lo, hi1, lo1; static u32 f[32];
static u32 g_acc;                       // EE FPU accumulator (ACC)
// max.s/min.s order raw bit patterns: unsigned for positives, reversed for
// negatives. Done on bits so +0 and -0 stay distinct, as on hardware.
static inline s64 FPKEY(u32 b){
    return (b & 0x80000000u) ? -(s64)(b & 0x7fffffffu) : (s64)(b & 0x7fffffffu);
}
static const u64 ZERO = 0;
static bool fcc, cond;
// ---- the 128-bit MMI unit -------------------------------------------
// A register's full width is rq[n] over r[n]. QW never writes register 0, so
// Q(0) stays the hardwired zero the interpreter also reports.
typedef unsigned __int128 u128;
static u32 g_sa;                     // shift-amount register: MTSAB -> QFSRV
static inline u128 Q(int n) { return ((u128)rq[n] << 64) | r[n]; }
static inline void QW(int n, u128 v) { if (n) { r[n] = (u64)v; rq[n] = (u64)(v >> 64); } }
static inline s64 SX(u64 e, int w) { return (s64)(e << (64 - w)) >> (64 - w); }
// Element-wise across the 128 bits. W is 8, 16 or 32; the whole-register
// bitwise ops are emitted directly instead.
template <int W, class F> static inline u128 PEW(u128 x, u128 y, F f) {
    const u64 m = (1ull << W) - 1;
    u128 out = 0;
    for (int i = 0; i < 128 / W; i++)
        out |= (u128)(f((u64)(x >> (W * i)) & m, (u64)(y >> (W * i)) & m) & m) << (W * i);
    return out;
}
// PEXTL*/PEXTU*: interleave one half of rt (even slots) and rs (odd slots).
static inline u128 PEXT(u128 x, u128 y, int W, int up) {
    const u64 m = (W == 32) ? 0xffffffffull : 0xffull;
    const int h = 64 / W, base = up ? h : 0;
    u128 out = 0;
    for (int i = 0; i < h; i++) {
        out |= (u128)((u64)(y >> (W * (base + i))) & m) << (W * (2 * i));
        out |= (u128)((u64)(x >> (W * (base + i))) & m) << (W * (2 * i + 1));
    }
    return out;
}
static inline u128 PPACB(u128 x, u128 y) {      // low byte of each halfword
    u128 out = 0;
    for (int i = 0; i < 8; i++) {
        out |= (u128)((u64)(y >> (16 * i)) & 0xff) << (8 * i);
        out |= (u128)((u64)(x >> (16 * i)) & 0xff) << (8 * i + 64);
    }
    return out;
}
static inline u128 PCPYH(u128 t) {
    const u64 rep = 0x0001000100010001ull;
    return ((u128)(((u64)(t >> 64) & 0xffff) * rep) << 64) | (((u64)t & 0xffff) * rep);
}
static inline u128 QFSRV(u128 x, u128 y, u32 s) {   // (x:y) >> s, low 128 bits
    if (s == 0) return y;
    if (s >= 128) return (s >= 256) ? (u128)0 : (x >> (s - 128));
    return (y >> s) | (x << (128 - s));
}
// ---- VU0 macro mode --------------------------------------------------
// 32 four-wide float registers with VF00 hardwired to (0,0,0,1), a wide
// accumulator, and the control registers CFC2 can read. Reading an operand
// uses B2F: the VU flushes denormal inputs and cannot see Inf or NaN, which
// is the same rule the EE FPU follows. Writing a result adds the four
// per-component flags (zero / sign / underflow / overflow) the MAC register
// keeps, and those drive the status word in vi[16].
static u32 vf[32][4] = {{0, 0, 0, 0x3f800000u}}, vacc[4], vi[32], vq, vmac;
static const double VU_2P128 = 3.40282366920938463e+38;  // 2^128
static inline u32 VRES(int i, double d) {
    u32 b; int n;
    if (std::fabs(d) >= VU_2P128) {          // exponent overflow: no Inf here
        b = std::signbit(d) ? 0xff7fffffu : 0x7f7fffffu;
        n = 8;
    } else {
        float y = (float)d;
        if (std::fabs((double)y) > std::fabs(d))   // chop, never away from 0
            y = std::nextafterf(y, 0.0f);
        b = F2B(y);
        if (b & 0x7f800000u) n = 0;
        else { n = (b & 0x7fffffu) ? 5 : 1; b &= 0x80000000u; }
    }
    n |= (b >> 30) & 2;
    const int sh = 3 - i;
    vmac = (vmac & ~(0x1111u << sh)) | ((u32)(n & 1) << sh)
         | ((u32)((n >> 1) & 1) << (4 + sh)) | ((u32)((n >> 2) & 1) << (8 + sh))
         | ((u32)((n >> 3) & 1) << (12 + sh));
    return b;
}
static inline void VMCLR(int i) { vmac &= ~(0x1111u << (3 - i)); }
static inline void VSTAT() {          // bits 3:0 now, 9:6 sticky, 5:4 from DIV
    u32 n = (vmac & 0x000fu ? 1u : 0u) | (vmac & 0x00f0u ? 2u : 0u)
          | (vmac & 0x0f00u ? 4u : 0u) | (vmac & 0xf000u ? 8u : 0u);
    vi[16] = (vi[16] & 0xff0u) | n | (n << 6);
}
// The product of a MADD is rounded to a VU float before the accumulator is
// applied -- the multiply-add is not fused.
static inline double VMUL(u32 a, u32 b) {
    return (double)B2F(FSAT((double)B2F(a) * (double)B2F(b)));
}
// MIN/MAX select a bit pattern outright: no rounding, no flags. Float bit
// patterns sort as signed ints for positives and in reverse for negatives.
static inline u32 VMAX(u32 a, u32 b) {
    s32 x = (s32)a, y = (s32)b;
    return (x < 0 && y < 0) ? (x <= y ? a : b) : (x >= y ? a : b);
}
static inline u32 VMIN(u32 a, u32 b) {
    s32 x = (s32)a, y = (s32)b;
    return (x < 0 && y < 0) ? (x >= y ? a : b) : (x <= y ? a : b);
}
static inline u32 VFTOI(u32 b, int n) {      // -> n fraction bits, chopped
    float f; std::memcpy(&f, &b, 4);         // raw: a conversion, not an operand
    if (n) { f *= std::ldexp(1.0f, n); std::memcpy(&b, &f, 4); }
    if ((b & 0x7f800000u) >= 0x4f000000u)    // |value| >= 2^31, or not finite
        return (b & 0x80000000u) ? 0x80000000u : 0x7fffffffu;
    return (u32)(s32)f;
}
static inline u32 VITOF(u32 b, int n) {
    double d = (double)(s32)b;
    float y = (float)d;
    if (std::fabs((double)y) > std::fabs(d)) y = std::nextafterf(y, 0.0f);
    return FSAT((double)y * std::ldexp(1.0, -n));
}
// A zero divisor saturates rather than producing Inf, and raises D -- or I
// when the dividend is zero as well. sqrt takes the magnitude and raises I.
static inline void VDIV(u32 a, u32 b) {
    double t = (double)B2F(b);
    if (t == 0.0) {
        vq = ((a ^ b) & 0x80000000u) | 0x7f7fffffu;
        vi[16] = (vi[16] & 0xfcfu) | (B2F(a) == 0.0f ? 0x10u : 0x20u);
    } else {
        vq = FSAT((double)B2F(a) / t);
        vi[16] &= 0xfcfu;
    }
}
static inline void VSQRTQ(u32 b) {
    double t = (double)B2F(b);
    vq = FSAT(std::sqrt(std::fabs(t)));
    vi[16] = (vi[16] & 0xfcfu) | (t < 0.0 ? 0x10u : 0u);
}
// CLIP pushes six answers -- x, y and z each against +|w| and -|w| -- into a
// 24-bit shift register. Flipping the sign bit turns "below -|w|" into the
// same signed comparison. A denormal |w| clips nothing above it.
static inline void VCLIP(const u32* a, u32 w) {
    s32 lim = (w & 0x7f800000u) ? (s32)(w & 0x7fffffffu) : 0x007fffff;
    u32 c = 0;
    for (int i = 0; i < 3; i++) {
        if ((s32)a[i] > lim) c |= 1u << (2 * i);
        if ((s32)(a[i] ^ 0x80000000u) > lim) c |= 1u << (2 * i + 1);
    }
    vi[18] = ((vi[18] << 6) | c) & 0xffffffu;
}
'''

LOADS = {'lb': (1, 1), 'lbu': (1, 0), 'lh': (2, 1), 'lhu': (2, 0),
         'lw': (4, 1), 'lwu': (4, 0), 'ld': (8, 0)}
STORES = {'sb': 1, 'sh': 2, 'sw': 4, 'sd': 8}


def R(n):
    return 'ZERO' if n == '$zero' else f'r[{RN[n]}]'


def W(n, expr):
    """Assignment that silently drops writes to $zero, as the hardware does."""
    return '' if n == '$zero' else f'r[{RN[n]}] = (u64)({expr});'


def QR(n):
    """Read a register at its full 128-bit width."""
    return f'Q({RN[n]})'


def QW(n, expr):
    """128-bit write. QW() itself drops register 0, so $zero stays zero."""
    return f'QW({RN[n]}, {expr});'


# Per-element rules, kept in step with emu.PAR -- same widths, same arithmetic.
PAR_C = {
    'paddh':  (16, 'a + b'),
    'psubw':  (32, 'a - b'),
    'psubb':  (8,  'a - b'),
    'pcgth':  (16, 'SX(a, 16) > SX(b, 16) ? 0xffffull : 0ull'),
    'pmaxh':  (16, 'SX(a, 16) >= SX(b, 16) ? a : b'),
    'pminh':  (16, 'SX(a, 16) <= SX(b, 16) ? a : b'),
    'paddub': (8,  'a + b > 255 ? 255ull : a + b'),
}
BIT_C = {'pand': '{0} & {1}', 'por': '{0} | {1}', 'pxor': '{0} ^ {1}',
         'pnor': '~({0} | {1})'}


def F(n):
    return f'f[{int(n[2:])}]'


def mem(addr):
    o, b = (addr.split('(') + [''])[:2]
    b = b.rstrip(')')
    off = int(o, 0) if o.strip() else 0
    return f'({R(b)} + {off})'


def _stub_size(img, addr, maxsz=256):
    """Size an unnamed code stub: distance to the next known function start."""
    if not (img.base <= addr < img.base + img.size):
        return None                      # not code at all (misdecoded jal)
    import bisect
    starts = sorted(img.byaddr)
    i = bisect.bisect_right(starts, addr)
    nxt = starts[i] if i < len(starts) else img.base + img.size
    sz = nxt - addr
    return sz if 0 < sz <= maxsz else None


class Unliftable(Exception):
    pass


VU_XFER = ('lqc2', 'sqc2', 'qmfc2', 'qmtc2', 'cfc2', 'ctc2')


def _vn(x):
    """'$vf7' or '$vf7.z' -> (index, component index or None)."""
    r, _, c = x.partition('.')
    return int(r[3:]), ('xyzw'.index(c) if c else None)


def lift_vu(mn, p):
    """-> C++ for one VU0 macro-mode instruction, mirroring Emu.vstep."""
    from emu import VU_FM
    base, _, dest = mn[1:].partition('.')
    sel = [i for i in range(4) if 'xyzw'[i] in dest]

    if mn in ('vnop', 'vwaitq'):        # Q has no latency in this model
        return ';'
    if mn in ('lqc2', 'sqc2'):
        n = _vn(p[0])[0]
        a = f'(({mem(p[1])}) & ~15ull)'
        if mn == 'sqc2':
            return ' '.join(f'ST({a} + {4 * i}, 4, vf[{n}][{i}]);'
                            for i in range(4))
        if not n:
            return ';'
        return ' '.join(f'vf[{n}][{i}] = (u32)LD({a} + {4 * i}, 4, 0);'
                        for i in range(4))
    if mn in ('qmfc2', 'qmtc2'):
        n = _vn(p[1])[0]
        if mn == 'qmfc2':
            lo = f'((u64)vf[{n}][1] << 32) | vf[{n}][0]'
            hi = f'((u64)vf[{n}][3] << 32) | vf[{n}][2]'
            return f'QW({RN[p[0]]}, ((u128)(u64)({hi}) << 64) | (u64)({lo}));'
        if not n:
            return ';'
        return ' '.join(
            f'vf[{n}][{i}] = (u32)(Q({RN[p[0]]}) >> {32 * i});' for i in range(4))
    if mn in ('cfc2', 'ctc2'):
        n = _vn(p[1])[0]
        if n not in (16, 17, 18, 28, 29):
            raise Unliftable(f'{mn} of VI{n}: the VU integer unit is not modelled')
        if mn == 'cfc2':
            src = {17: 'vmac', 18: '(vi[18] & 0xffffffu)',
                   29: '0u'}.get(n, f'vi[{n}]')       # VPU_STAT: VU0 is idle
            return W(p[0], f'SX32({src})')
        if n == 29:
            return ';'                                # read-only
        v = f'(u32){R(p[0])}' + (' & 0x0c0cu' if n == 28 else '')
        return f'vi[{n}] = {v};'

    def comp(x, i):
        r, c = _vn(x)
        return f'vf[{r}][{i if c is None else c}]'

    if base in ('div', 'sqrt'):
        if base == 'sqrt':
            return f'VSQRTQ({comp(p[0], 0)});'
        return f'VDIV({comp(p[0], 0)}, {comp(p[1], 0)});'
    if base == 'clipw':
        return f'VCLIP(vf[{_vn(p[0])[0]}], {comp(p[1], 3)});'
    if base in ('move', 'mr32') or base[:4] in ('ftoi', 'itof'):
        n, m = _vn(p[0])[0], _vn(p[1])[0]
        if not n:
            return ';'
        if base == 'mr32':                  # x<-y<-z<-w<-x, so x needs saving
            body = ' '.join(f'vf[{n}][{i}] = _x{i};' for i in sel)
            src = ' '.join(f'const u32 _x{i} = vf[{m}][{(i + 1) & 3}];'
                           for i in sel)
            return '{ ' + src + ' ' + body + ' }'
        if base == 'move':
            return ' '.join(f'vf[{n}][{i}] = vf[{m}][{i}];' for i in sel)
        fn, k = ('VFTOI', base[4:]) if base[0] == 'f' else ('VITOF', base[4:])
        return ' '.join(f'vf[{n}][{i}] = {fn}(vf[{m}][{i}], {k});' for i in sel)
    if base in ('opmula', 'opmsub'):
        a, b = _vn(p[1])[0], _vn(p[2])[0]
        n = 0 if base == 'opmula' else _vn(p[0])[0]
        out = 'vacc' if base == 'opmula' else f'vf[{n}]'
        # Either source may also be the destination, so read both first.
        src = ' '.join(f'const u32 _a{i} = vf[{a}][{i}], _b{i} = vf[{b}][{i}];'
                       for i in range(3))
        body = []
        for i in range(3):
            j, k = (i + 1) % 3, (i + 2) % 3
            x = f'VMUL(_a{j}, _b{k})'
            e = (f'VRES({i}, {x})' if base == 'opmula'
                 else f'VRES({i}, (double)B2F(vacc[{i}]) - {x})')
            body.append(f'{out}[{i}] = {e};' if base == 'opmula' or n
                        else f'{e};')
        return '{ ' + src + ' ' + ' '.join(body) + ' VSTAT(); }'

    op, dsel, ssel = VU_FM[base]
    n = 0 if dsel == 'a' else _vn(p[0])[0]
    pre = ''
    if ssel == 'v':
        def snd(i):
            return comp(p[2], i)
    else:
        if ssel == 'q':
            b = 'vq'
        elif ssel == 'i':
            b = 'vi[21]'
        else:
            # A broadcast reads one component for all four, and the
            # destination may be that same register: latch it first.
            b = '_bc'
            pre = f'const u32 _bc = {comp(p[2], "xyzw".index(ssel))}; '

        def snd(i):
            return b
    if op in ('max', 'mini'):
        if not n:
            return ';'
        fn = 'VMAX' if op == 'max' else 'VMIN'
        body = ' '.join(f'vf[{n}][{i}] = {fn}({comp(p[1], i)}, {snd(i)});'
                        for i in sel)
        return '{ ' + pre + body + ' }' if pre else body
    out = 'vacc' if dsel == 'a' else f'vf[{n}]'
    body = []
    for i in range(4):
        if i not in sel:
            body.append(f'VMCLR({i});')
            continue
        a = comp(p[1], i)
        if op == 'add':
            x = f'(double)B2F({a}) + (double)B2F({snd(i)})'
        elif op == 'sub':
            x = f'(double)B2F({a}) - (double)B2F({snd(i)})'
        elif op == 'mul':
            x = f'(double)B2F({a}) * (double)B2F({snd(i)})'
        else:
            sign = '+' if op == 'madd' else '-'
            x = f'(double)B2F(vacc[{i}]) {sign} VMUL({a}, {snd(i)})'
        e = f'VRES({i}, {x})'
        body.append(f'{out}[{i}] = {e};' if dsel == 'a' or n else f'{e};')
    return '{ ' + pre + ' '.join(body) + ' VSTAT(); }'


def lift_one(mn, ops, pc, labels):
    """-> C++ statement for one non-branch instruction."""
    p = [x.strip() for x in ops.split(',')] if ops else []
    if mn[0] == 'v' or mn in VU_XFER:
        return lift_vu(mn, p)
    # `break 0, 7` is the divide-by-zero trap Metrowerks emits after every
    # div; it sits behind a branch and is unreachable for valid operands.
    if mn in ('nop', 'ehb', 'ssnop', 'sync', 'cache',
              'cop0nop', 'ei', 'di', 'mtc0', 'break', 'teq', 'tne'):
        return ';'
    if mn == 'mfc0':
        return W(p[0], '0')
    if mn == 'syscall':
        # Not stubbed -- refused at runtime. The interpreter raises on a
        # syscall, so if difftest ever reaches this the run is recorded as a
        # failure on both sides. Emitting it lets the (very common) case
        # where the syscall sits on an untaken path be verified honestly,
        # instead of discarding the whole function for an instruction that
        # never executes.
        return 'std::_Exit(97);   // syscall: unmodelled, fail loudly'
    if mn in ('lq', 'sq'):
        a = mem(p[1])
        if mn == 'sq':
            return f'ST(({a}) & ~15ull, 8, {R(p[0])}); ST((({a}) & ~15ull)+8, 8, rq[{RN[p[0]]}]);'
        return (f'{W(p[0], f"LD(({a}) & ~15ull, 8, 0)")} '
                f'rq[{RN[p[0]]}] = LD((({a}) & ~15ull)+8, 8, 0);')
    if mn in ('swl', 'swr', 'sdl', 'sdr'):
        wd = 4 if mn.startswith('sw') else 8
        return f"{'SWL' if mn.endswith('l') else 'SWR'}({R(p[0])}, {mem(p[1])}, {wd});"
    if mn in ('lwl', 'lwr', 'ldl', 'ldr'):
        wd = 4 if mn.startswith('lw') else 8
        fnm = 'LWL' if mn.endswith('l') else 'LWR'
        mask = '0xffffffffull' if wd == 4 else '~0ull'
        expr = f'{fnm}({R(p[0])} & {mask}, {mem(p[1])}, {wd})'
        return W(p[0], f'SX32({expr})' if wd == 4 else expr)
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
        return (f'{F(p[0])} = (!(({F(p[2])}) & 0x7f800000u)) '
                f'? (0x7f7fffffu | ((({F(p[1])}) ^ ({F(p[2])})) & 0x80000000u)) '
                f': FSAT((double)B2F({F(p[1])}) / (double)B2F({F(p[2])}));')
    if mn in ('adda.s', 'suba.s', 'mula.s'):
        op = {'adda.s': '+', 'suba.s': '-', 'mula.s': '*'}[mn]
        return f'g_acc = FSAT((double)B2F({F(p[0])}) {op} (double)B2F({F(p[1])}));'
    if mn in ('madda.s', 'msuba.s'):
        op = '+' if mn == 'madda.s' else '-'
        return (f'{{ u32 _p = FSAT((double)B2F({F(p[0])}) * (double)B2F({F(p[1])})); '
                f'g_acc = FSAT((double)B2F(g_acc) {op} (double)B2F(_p)); }}')
    if mn in ('madd.s', 'msub.s'):
        # Not fused: the EE rounds the product, then rounds the sum.
        op = '+' if mn == 'madd.s' else '-'
        return (f'{{ u32 _p = FSAT((double)B2F({F(p[1])}) * (double)B2F({F(p[2])})); '
                f'{F(p[0])} = FSAT((double)B2F(g_acc) {op} (double)B2F(_p)); }}')
    if mn == 'sqrt.s':
        return (f'{F(p[0])} = (!(({F(p[1])}) & 0x7f800000u)) '
                f'? (({F(p[1])}) & 0x80000000u) '
                f': FSAT(std::sqrt(std::fabs((double)B2F({F(p[1])}))));')
    if mn in ('max.s', 'min.s'):
        cmp = '>' if mn == 'max.s' else '<'
        return (f'{F(p[0])} = (FPKEY({F(p[1])}) {cmp} FPKEY({F(p[2])})) '
                f'? {F(p[1])} : {F(p[2])};')
    if mn == 'abs.s':
        return f'{F(p[0])} = {F(p[1])} & 0x7fffffffu;'
    if mn == 'neg.s':
        return f'{F(p[0])} = {F(p[1])} ^ 0x80000000u;'
    if mn == 'mov.s':
        return f'{F(p[0])} = {F(p[1])};'
    if mn == 'cvt.s.w':
        return f'{F(p[0])} = F2B((float)(s32){F(p[1])});'
    if mn in ('cvt.w.s', 'trunc.w.s'):
        return (f'{F(p[0])} = ((({F(p[1])}) & 0x7f800000u) <= 0x4e800000u) '
                f'? (u32)(s32)B2F({F(p[1])}) '
                f': ((({F(p[1])}) & 0x80000000u) ? 0x80000000u : 0x7fffffffu);')
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
    if mn in ('addiu', 'addi'):
        return W(p[0], f'SX32({R(p[1])} + ({int(p[2], 0)}ll))')
    if mn in ('daddiu', 'daddi'):          # true 64-bit: no truncation
        return W(p[0], f'{R(p[1])} + ({int(p[2], 0)}ll)')
    if mn in ('addu', 'add'):
        return W(p[0], f'SX32({R(p[1])} + {R(p[2])})')
    if mn in ('daddu', 'dadd'):
        return W(p[0], f'{R(p[1])} + {R(p[2])}')
    if mn in ('subu', 'sub'):
        return W(p[0], f'SX32({R(p[1])} - {R(p[2])})')
    if mn in ('dsubu', 'dsub'):
        return W(p[0], f'{R(p[1])} - {R(p[2])}')
    if mn == 'negu':
        return W(p[0], f'SX32(-{R(p[1])})')
    if mn == 'not':
        return W(p[0], f'~{R(p[1])}')
    # 64-bit comparisons, matching MIPS III (see emu.py)
    if mn == 'sltiu':
        return W(p[0], f'((u64){R(p[1])} < (u64){int(p[2], 0) & 0xffffffffffffffff}ull) ? 1 : 0')
    if mn == 'slti':
        return W(p[0], f'((s64){R(p[1])} < (s64)({int(p[2], 0)}ll)) ? 1 : 0')
    if mn == 'sltu':
        return W(p[0], f'((u64){R(p[1])} < (u64){R(p[2])}) ? 1 : 0')
    if mn == 'slt':
        return W(p[0], f'((s64){R(p[1])} < (s64){R(p[2])}) ? 1 : 0')
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
        return W(p[0], f'SX32({int(p[1], 0)}u << 16)')
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
    if mn in ('madd', 'maddu'):
        c = 's64)(s32' if mn == 'madd' else 'u64)(u32'
        return (f'{{ u64 _s = ((u64)(u32)hi << 32 | (u32)lo) + '
                f'(u64)(({c}){R(p[1])} * ({c}){R(p[2])}); '
                f'lo = (s64)(s32)_s; hi = (s64)(s32)(u32)(_s >> 32); '
                f'{W(p[0], "lo")} }}')
    # ---- 128-bit parallel (MMI) ops ----------------------------------
    if mn in PAR_C:
        w, body = PAR_C[mn]
        return QW(p[0], f'PEW<{w}>({QR(p[1])}, {QR(p[2])}, '
                        f'[](u64 a, u64 b) -> u64 {{ return {body}; }})')
    if mn in BIT_C:
        return QW(p[0], BIT_C[mn].format(QR(p[1]), QR(p[2])))
    if mn in ('psllh', 'psrlh', 'psrah'):
        sh = int(p[2], 0) & 15
        body = {'psllh': f'a << {sh}', 'psrlh': f'a >> {sh}',
                'psrah': f'(u64)(SX(a, 16) >> {sh})'}[mn]
        return QW(p[0], f'PEW<16>({QR(p[1])}, 0, '
                        f'[](u64 a, u64) -> u64 {{ return {body}; }})')
    if mn in ('pextlb', 'pextub', 'pextlw', 'pextuw'):
        w = 8 if mn.endswith('b') else 32
        return QW(p[0], f'PEXT({QR(p[1])}, {QR(p[2])}, {w}, {int(mn[4] == "u")})')
    if mn == 'ppacb':
        return QW(p[0], f'PPACB({QR(p[1])}, {QR(p[2])})')
    if mn == 'pcpyld':
        return QW(p[0], f'((u128){R(p[1])} << 64) | {R(p[2])}')
    if mn == 'pcpyud':
        return QW(p[0], f'((u128)(u64)({QR(p[2])} >> 64) << 64) '
                        f'| (u64)({QR(p[1])} >> 64)')
    if mn == 'pcpyh':
        return QW(p[0], f'PCPYH({QR(p[2])})')
    if mn in ('mtsab', 'mtsah'):
        m, mul = (0xf, 8) if mn == 'mtsab' else (0x7, 16)
        return f'g_sa = (((u32){R(p[0])} & {m}u) ^ ({int(p[1], 0) & m}u)) * {mul}u;'
    if mn == 'qfsrv':
        return QW(p[0], f'QFSRV({QR(p[1])}, {QR(p[2])}, g_sa)')
    if mn == 'mthi':
        return 'hi = ' + R(p[0]) + ';'
    if mn == 'mtlo':
        return 'lo = ' + R(p[0]) + ';'
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


# ---- jump tables (switch statements) ---------------------------------------
#
# Metrowerks MIPS 2.4.1 emits exactly one shape for a dense switch:
#
#     sltiu $at, $idx, N        ; bounds check, N = entry count
#     beqz  $at, default        ; (not necessarily adjacent to the sltiu)
#     lui   $v1, HI
#     sll   $v0, $idx, 2
#     addiu $v1, $v1, LO        ; base = HI<<16 + LO ...
#     addu  $v0, $v0, $v1
#     lw    $v0, ($v0)
#     jr    $v0
#
# with one variant that folds the low half into the load instead:
#
#     lui   $v1, HI
#     sll   $v0, $idx, 2
#     addu  $v1, $v1, $v0
#     lw    $v1, LO($v1)        ; ... base = HI<<16 + LO here too
#     jr    $v1
#
# Both are recovered by walking back from the `jr` over reaching definitions.
# The table itself is N absolute addresses in the ELF's data.

BRANCHES = set(COND_C) | {b + 'l' for b in COND_C} | {
    'b', 'j', 'jal', 'jr', 'jalr', 'bal', 'bc1t', 'bc1f', 'bc1tl', 'bc1fl'}
# Instructions whose first operand is a source, not a destination -- everything
# else is assumed to write p[0], which over-approximates and so only ever makes
# the backward walk give up early.
NO_DEST = (set(STORES) | BRANCHES | {
    'sq', 'swc1', 'nop', 'sync', 'cache', 'break', 'teq', 'tne', 'ei', 'di',
    'mtc0', 'cop0nop', 'ssnop', 'ehb', 'mult', 'multu', 'div', 'divu',
    'div1', 'divu1', 'mtc1', 'mthi1', 'mtlo1', 'lwc1'})


def _dest(mn, p):
    """Register mn writes, or None. Over-approximates on purpose."""
    if mn in NO_DEST or mn.startswith('c.') or mn.endswith('.s'):
        return None
    return p[0] if p and p[0].startswith('$') else None


def _walk(ins, lo, pc):
    """Yield (q, mn, p) backwards from pc-4 to lo. Stops at a call."""
    q = pc - 4
    while q >= lo:
        mn, ops = ins[q]
        if mn in ('jal', 'jalr', 'bal'):     # clobbers the caller-saved set
            return
        yield q, mn, [x.strip() for x in ops.split(',')] if ops else []
        q -= 4


def _def(ins, lo, pc, reg):
    """Address of the last instruction before pc that writes reg, else None."""
    for q, mn, p in _walk(ins, lo, pc):
        if _dest(mn, p) == reg:
            return q
    return None


def _konst(ins, lo, pc, reg, depth=0):
    """Constant value of reg at pc, following lui/addiu/ori chains."""
    if reg == '$zero':
        return 0
    if depth > 4:
        return None
    q = _def(ins, lo, pc, reg)
    if q is None:
        return None
    mn, ops = ins[q]
    p = [x.strip() for x in ops.split(',')]
    if mn == 'lui':
        return (int(p[1], 0) << 16) & 0xffffffff
    if mn == 'li':
        return int(p[1], 0) & 0xffffffff
    if mn in ('addiu', 'addi', 'ori', 'daddiu'):
        b = _konst(ins, lo, q, p[1], depth + 1)
        if b is None:
            return None
        i = int(p[2], 0)
        return (b | (i & 0xffff)) & 0xffffffff if mn == 'ori' else (b + i) & 0xffffffff
    return None


def _memop(s):
    """'-0x10($v1)' or '($v1)' -> (offset, register)."""
    o, _, b = s.partition('(')
    return (int(o, 0) if o.strip() else 0), b.rstrip(')')


def jump_table(ins, img, addr, size, pc, reg):
    """Recover the switch behind `jr reg` at pc.

    -> (index register, address of the `sll` that scales it, [targets]).
    Raises Unliftable unless every piece is proven: base, entry count, and
    every entry landing inside this function.
    """
    def no(why):
        raise Unliftable(f'jr at {pc:#x} (jump table: {why})')

    lo = addr
    q = _def(ins, lo, pc, reg)
    if q is None or ins[q][0] != 'lw':
        no('target is not a table load')
    off, breg = _memop(ins[q][1].split(',')[1].strip())

    d = _def(ins, lo, q, breg)
    if d is None or ins[d][0] not in ('addu', 'add', 'daddu', 'dadd'):
        no('table address is not base+index')
    dp = [x.strip() for x in ins[d][1].split(',')]

    base = idx = sll_pc = None
    for cr, sr in ((dp[1], dp[2]), (dp[2], dp[1])):
        b = _konst(ins, lo, d, cr)
        s = _def(ins, lo, d, sr)
        if b is None or s is None:
            continue
        sp = [x.strip() for x in ins[s][1].split(',')]
        if ins[s][0] == 'sll' and int(sp[2], 0) == 2:
            base, idx, sll_pc = (b + off) & 0xffffffff, sp[1], s
            break
    if base is None:
        no('cannot prove the table base')
    if idx == '$zero':
        no('index is $zero')
    # A scaling `sll` in a delay slot may be squashed by a likely branch, which
    # would make the captured index stale. Not worth proving; refuse.
    if sll_pc - 4 >= lo and ins[sll_pc - 4][0] in BRANCHES:
        no('index scaled in a delay slot')

    # Entry count: the nearest `beqz` before the jr guards the table, and the
    # register it tests is set by the `sltiu` that holds the count.
    n = None
    for q2, mn, p in _walk(ins, lo, pc):
        if mn not in BRANCHES:
            continue
        # `beqz r` and its branch-likely spelling; capstone prints the latter
        # unfused as `beql r, $zero`.
        if mn in ('beqz', 'beqzl') or (mn in ('beq', 'beql') and p[1] == '$zero'):
            c = _def(ins, lo, q2, p[0])
            if c is not None and ins[c][0] == 'sltiu':
                cp = [x.strip() for x in ins[c][1].split(',')]
                if cp[1] == idx:
                    # the index must not be recomputed between check and use
                    r = _def(ins, lo, sll_pc, idx)
                    if r is None or r <= c:
                        n = int(cp[2], 0)
        break                       # only the branch guarding the jr counts
    if not n or n > 1024:
        no('cannot prove the entry count')

    if not (img.base <= base and base + 4 * n <= img.base + img.size):
        no(f'table at {base:#x} is outside the image')
    ents = []
    for i in range(n):
        w = img.read(base + 4 * i, 4)
        if len(w) < 4:
            no(f'table at {base:#x} is outside the image')
        t, = struct.unpack('<I', w)
        if t % 4 or not (addr <= t < addr + size):
            no(f'entry {i} -> {t:#x} is outside the function')
        ents.append(t)
    return idx, sll_pc, ents


def lift_body(m, img, addr, size, callees, indirect=None):
    """Emit one function's body. Records call targets in `callees`.

    `indirect` is the profiled jalr target set; without it a jalr is
    unliftable rather than guessed at."""
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

    # Jump tables, before emission: their targets need labels too, and the
    # index must be captured at the `sll` because the pattern reuses (and so
    # destroys) the index register before the `jr`.
    tables, capture, traps = {}, {}, {}
    for pc, (mn, ops) in ins.items():
        if mn == 'jr' and ops.strip() != '$ra':
            try:
                idx, sll_pc, ents = jump_table(ins, img, addr, size, pc,
                                               ops.strip())
            except Unliftable as ex:
                # No provable table. Refusing the whole function discards
                # everything on the normal path, and the single largest case
                # is the `jr $a2` in Metrowerks' __TransferControl -- the C++
                # throw path, which no non-throwing test case enters. Emit a
                # loud exit instead, the same contract an unprofiled jalr
                # already gets: reaching it kills the driver, and difftest
                # reports a short result list rather than a pass.
                traps[pc] = str(ex)
                continue
            tables[pc] = ents
            capture[sll_pc] = idx
            labels.update(ents)

    def stmt(q):
        """One instruction, with the jump-table index capture spliced in."""
        s = lift_one(*ins[q], q, labels)
        return f'_jt = (u32){R(capture[q])}; {s}' if q in capture else s

    def delay_reentry(pc, body):
        """Handle a branch whose target is another branch's delay slot.

        Folding the slot into the branch consumes pc+4, so its label is never
        emitted and anything jumping there fails to compile. MIPS lets a
        branch target a delay slot, and hand-written SCE runtime code does it
        (sceSifWriteBackDCache, for one). Emit a second copy of the slot
        behind its own label -- reachable only by that jump, since the
        fall-through path skips over it.
        """
        d = pc + 4
        if d not in labels:
            return
        after = pc + 8
        if after >= addr + size:
            body.append('  goto L_done;')
        else:
            labels.add(after)
            body.append(f'  goto L_{after:x};')
        body.append(f'L_{d:x}:;')
        body.append('  ' + stmt(d))

    body = ['  u32 _jt = 0; (void)_jt;'] if tables else []
    pc = addr
    while pc < addr + size:
        mn, ops = ins[pc]
        if pc in labels:
            body.append(f'L_{pc:x}:;')
        p = [x.strip() for x in ops.split(',')] if ops else []
        nxt = ins.get(pc + 4)

        if pc in traps:
            body.append(f'  // UNRESOLVED INDIRECT JUMP: {traps[pc]}')
            body.append('  std::_Exit(97);')
            # Advance by one, not two: the delay slot then emits normally as
            # dead code, which keeps its label reachable for any branch that
            # targets it.
            pc += 4
            continue

        if pc in tables:
            if nxt:
                body.append('  ' + stmt(pc + 4))     # delay slot runs first
            body.append('  switch (_jt) {')
            for i, t in enumerate(tables[pc]):
                body.append(f'  case {i}: goto L_{t:x};')
            body.append('  default: std::_Exit(97);')  # bounds check says never
            body.append('  }')
            delay_reentry(pc, body)
            pc += 8
            continue
        if mn == 'jr' and p and p[0] == '$ra':
            if nxt:
                body.append('  ' + stmt(pc + 4))
            body.append('  goto L_done;')
            delay_reentry(pc, body)
            pc += 8
            continue
        if mn in ('jal', 'bal'):
            t = int(ops, 0)
            if t not in img.byaddr:
                # A handful of unnamed compiler stubs (abort/unwind helpers)
                # live between symbols. Size them to the next symbol start.
                sz2 = _stub_size(img, t)
                if sz2 is None:
                    raise Unliftable(f'{mn} to unknown target {t:#x}')
                img.byaddr[t] = (f'stub_{t:x}', sz2)
            callees.add(t)
            if nxt:                      # delay slot runs before the call
                body.append('  ' + stmt(pc + 4))
            body.append(f'  fn_{t:x}();')
            delay_reentry(pc, body)
            pc += 8
            continue
        if mn == 'j' and ops.startswith('0x') and int(ops, 0) not in labels:
            t = int(ops, 0)              # tail call: run it, then return
            if t not in img.byaddr:
                raise Unliftable(f'tail call to unknown target {t:#x}')
            callees.add(t)
            if nxt:
                body.append('  ' + stmt(pc + 4))
            body.append(f'  fn_{t:x}();')
            body.append('  goto L_done;')
            delay_reentry(pc, body)
            pc += 8
            continue
        if mn == 'jalr':
            # An empty profile is fine: it means the call sits on a path the
            # test inputs never take. dispatch() then has only its default,
            # so if difftest ever does reach it the run exits loudly instead
            # of dispatching somewhere invented.
            if indirect is None:
                raise Unliftable('jalr (callee not profiled)')
            reg = p[-1]
            if nxt:                          # delay slot runs before the call
                body.append('  ' + stmt(pc + 4))
            body.append(f'  dispatch((u32){R(reg)});')
            for t in indirect:
                callees.add(t)
            delay_reentry(pc, body)
            pc += 8
            continue
        if mn == 'jr':
            raise Unliftable('jr (indirect jump)')
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
                s = stmt(pc + 4)
                body.append(f'  if (cond) {{ {s} }}' if likely else '  ' + s)
            body.append(f'  if (cond) goto L_{t:x};')
            delay_reentry(pc, body)
            pc += 8
            continue
        if mn == 'b':
            t = int(ops, 0)
            if t not in labels:
                raise Unliftable('branch out of function')
            if nxt:
                body.append('  ' + stmt(pc + 4))
            body.append(f'  goto L_{t:x};')
            delay_reentry(pc, body)
            pc += 8
            continue
        body.append('  ' + stmt(pc))
        pc += 4

    return body


# Measured: the call graphs that were being refused have a median of 126
# functions and a p90 of 311, so 48 was rejecting ordinary code, not runaways.
# Memory scales with parallel workers, not with one graph, so this can be
# generous when the batch is not heavily parallel.
MAX_FUNCS = int(os.environ.get('LIFT_MAX_FUNCS', 1200))


def profile_indirect(img, addr, size, objsize, cases=100):
    """Record which targets a jalr actually reaches.

    An indirect call has no static target, but it is not unknowable: run the
    function over the very object states difftest will use and watch where it
    goes. Anything unprofiled hits the dispatch default and fails loudly, so
    this can only under-approximate, never silently mis-dispatch.
    """
    import random
    from emu import Emu, Machine
    from difftest import obj_words, OBJ_ADDR
    from disasm import vtables
    vt = vtables(img)
    rng = random.Random(20020513)
    seen = set()
    for i in range(cases):
        blob = obj_words(rng, objsize or 4, vt[i % len(vt)] if vt else None)
        arg = rng.choice([0, 1, 2, 3, 4, 5, 7, 255, 1000])
        e = Emu(img, Machine(img))
        e.indirect = seen
        for j, b in enumerate(blob):
            e.m.wb(OBJ_ADDR + j, b)
        try:
            e.run(addr, size, [OBJ_ADDR, arg], [float(arg)], limit=120000)
        except Exception:
            pass
    return {t for t in seen if t in img.byaddr}


def lift(elf, func, objsize=0):
    img = Image(elf)
    m = Machine(img)
    sym, addr, size = img.func(func)
    cls, meth = demangle(sym)

    # Profile indirect calls first: the emitter needs to know which
    # targets a jalr can actually reach before it can dispatch to them.
    # Profiling costs ~100 interpreted runs, so only pay it when a jalr is
    # actually reachable. Walk the static call graph first -- cheap, and it
    # never misses one, since an indirect call still has to sit in some body
    # reached by direct calls.
    def _has_jalr(a0, sz0, seen=None, depth=0):
        # No depth cap: emission walks the whole graph (up to MAX_FUNCS), so
        # a jalr sitting deeper than the cap went undetected, profiling never
        # ran, and the lift refused with "callee not profiled" -- 127 of them.
        # `seen` already bounds the walk, and m.ins caches the decode.
        seen = seen if seen is not None else set()
        if a0 in seen:
            return False
        seen.add(a0)
        for pc in range(a0, a0 + sz0, 4):
            try:
                mn, ops = m.ins(pc)
            except Exception:
                continue
            if mn == 'jalr':
                return True
            if mn in ('jal', 'bal') and ops.startswith('0x'):
                t = int(ops, 0)
                if t in img.byaddr and _has_jalr(t, img.byaddr[t][1], seen, depth + 1):
                    return True
        return False

    indirect = (profile_indirect(img, addr, size, objsize)
                if _has_jalr(addr, size) else None)

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
        # The profile records every jalr target reached anywhere in the run,
        # callees included, so the same set is valid for all of them.
        bodies[a] = lift_body(m, img, a, sz, callees, indirect)
        for t in callees:
            if t not in seen:
                todo.append((t, img.byaddr[t][1]))

    name = f'{cls}::{meth}' if cls else meth
    imgpath = os.path.abspath(elf).replace(chr(92), '/')
    out = [PROLOGUE % (f'0x{addr:08x}  ({name}, {size} bytes, '
                       f'{len(bodies)} function(s) lifted)',
                       imgpath, img.base, img.size, img.off,
                       OBJ_ADDR, OBJ_ADDR, OBJ_ADDR,
                       STACK_TOP, STACK_TOP, STACK_TOP)]
    for a in bodies:                                   # forward declarations
        out.append(f'static void fn_{a:x}(void);')
    if any('dispatch(' in s for b in bodies.values() for s in b):
        out.append('// Indirect calls: the profiled target set. Anything not')
        out.append('// seen while profiling exits loudly, never mis-dispatches.')
        out.append('static void dispatch(u32 t) {')
        out.append('  switch (t) {')
        for t in sorted(indirect):
            if t in bodies:
                out.append(f'    case {t:#x}u: fn_{t:x}(); return;')
        out.append('    default: std::_Exit(97);')
        out.append('  }')
        out.append('}')
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
    out.append('  std::memset(f, 0, sizeof(f)); hi = lo = hi1 = lo1 = 0; g_acc = 0; g_sa = 0;')
    out.append('  fcc = cond = false;')
    out.append(f'  r[{RN["$a0"]}] = {OBJ_ADDR}ull; r[{RN["$a1"]}] = arg;')
    # must match difftest.ARGS() exactly
    out.append(f'  r[{RN["$a2"]}] = (u32)((arg + 3) & 0x7f); r[{RN["$a3"]}] = (u32)((arg + 7) & 0x7f);')
    out.append(f'  r[{RN["$sp"]}] = {STACK_TOP}ull;')
    out.append(f'  r[{RN["$gp"]}] = {m.gp}ull;')
    out.append('  f[12] = F2B((float)arg);')
    out.append(f'  fn_{addr:x}();')
    out.append(f'  return (unsigned)(u32)r[{RN["$v0"]}];')
    out.append('}')
    return '\n'.join(out)


def selftest(elf='disc/SCUS_972.05'):
    """Check jump-table recovery against tables read out of the ROM by hand.

    Each case is (function, jr site, index register, table base, entry count),
    taken from the disassembly. A silently wrong table is the one failure mode
    worth a fixed test: it compiles, runs, and jumps to the wrong case.
    """
    img = Image(elf)
    m = Machine(img)
    cases = [
        # base+count in the addiu; index reg is reused for the scaled offset
        ('ConvErr',                   0x33a7ac, '$v1', 0x45c180, 0x27),
        ('CSealCtrl::GetCommandName', 0x282d60, '$v0', 0x452ef0, 0x42),
        # low half folded into the lw displacement instead of an addiu
        ('MapMsgClientFailureReason', 0x41b14c, '$a1', 0x469030, 0x07),
        # bounds check sits ~22 instructions above the branch that uses it
        ('CAiSFlee::Tick',            0x2e5928, '$s0', 0x457f70, 0x07),
    ]
    for name, jr, idx, base, n in cases:
        _s, addr, size = img.func(name)
        ins = {pc: m.ins(pc) for pc in range(addr, addr + size, 4)}
        gi, _sll, ents = jump_table(ins, img, addr, size, jr, ins[jr][1].strip())
        assert gi == idx, (name, gi, idx)
        assert len(ents) == n, (name, len(ents), n)
        want = [struct.unpack('<I', img.read(base + 4 * i, 4))[0] for i in range(n)]
        assert ents == want, (name, ents[:4], want[:4])
        assert all(addr <= t < addr + size for t in ents), name

    # Damage each half of the pattern in turn: every one must refuse rather
    # than guess. 0x282d4c is the lui, 0x282d54 the addiu, 0x282d44 the sltiu.
    _s, addr, size = img.func('CSealCtrl::GetCommandName')
    for kill, want in ((0x282d4c, 'table base'), (0x282d44, 'entry count'),
                       (0x282d54, 'outside the function')):
        ins = {pc: m.ins(pc) for pc in range(addr, addr + size, 4)}
        ins[kill] = ('nop', '')
        try:
            jump_table(ins, img, addr, size, 0x282d60, '$v0')
            raise AssertionError(f'expected Unliftable with {kill:#x} erased')
        except Unliftable as e:
            assert want in str(e), (hex(kill), e)

    src = lift(elf, 'ConvErr')
    assert 'switch (_jt)' in src and src.count('case ') == 0x27, 'no switch emitted'


def demo():
    """Smoke-check the emitter. Behaviour is judged by difftest.py, which
    compiles this output and races it against emu.py; what is checked here is
    that each mnemonic emits at all and lands on the right registers."""
    def one(mn, ops):
        return lift_one(mn, ops, 0, set())

    assert one('addiu', '$v0, $a0, 1') == 'r[2] = (u64)(SX32(r[4] + (1ll)));'
    assert one('move', '$zero, $a0') == ''            # writes to $zero vanish
    # Every MMI mnemonic emu.py decodes must also lift.
    from emu import MMI_SUB, MMI_SHIFT
    for mnem in set(MMI_SUB.values()) | set(MMI_SHIFT.values()) | \
            {'madd', 'maddu', 'mtsab', 'mtsah'}:
        ops = ('$v0, $a0, 3' if mnem in MMI_SHIFT.values() else
               '$a0, 0' if mnem.startswith('mtsa') else '$v0, $a0, $a1')
        assert one(mnem, ops), mnem
    # 128-bit ops must go through Q()/QW(), never the 64-bit r[] path.
    assert one('pnor', '$v0, $a0, $a1') == 'QW(2, ~(Q(4) | Q(5)));'
    assert one('pand', '$v0, $a0, $a1') == 'QW(2, Q(4) & Q(5));'
    assert one('psubw', '$v0, $a0, $a1') == \
        'QW(2, PEW<32>(Q(4), Q(5), [](u64 a, u64 b) -> u64 { return a - b; }));'
    assert one('pextlb', '$v0, $zero, $a1') == 'QW(2, PEXT(Q(0), Q(5), 8, 0));'
    assert one('pextuw', '$v0, $a0, $a1') == 'QW(2, PEXT(Q(4), Q(5), 32, 1));'
    assert one('psrah', '$v0, $a0, 15') == \
        'QW(2, PEW<16>(Q(4), 0, [](u64 a, u64) -> u64 ' \
        '{ return (u64)(SX(a, 16) >> 15); }));'
    assert one('qfsrv', '$v0, $a0, $a1') == 'QW(2, QFSRV(Q(4), Q(5), g_sa));'
    assert one('mtsab', '$t5, 0') == 'g_sa = (((u32)r[13] & 15u) ^ (0u)) * 8u;'
    assert 'hi = (s64)(s32)(u32)(_s >> 32)' in one('madd', '$v0, $a0, $a1')

    # ---- VU0 macro mode -------------------------------------------------
    # Every word emu.py is willing to decode must also lift: synthesise one
    # instruction per table entry rather than trusting a hand-written list.
    from emu import VU_S1, VU_S2, decode_mmi
    seen = set()
    for tbl, esc in ((VU_S1, 0), (VU_S2, 1)):
        for key in tbl:
            if esc:
                w = (0x12 << 26) | (1 << 25) | (0xa << 21) | (3 << 16) | \
                    (4 << 11) | ((key >> 2) << 6) | 0x3c | (key & 3)
            else:
                w = (0x12 << 26) | (1 << 25) | (0xa << 21) | (3 << 16) | \
                    (4 << 11) | (5 << 6) | key
            mn, ops = decode_mmi(struct.pack('<I', w))
            seen.add(mn.split('.')[0])
            assert one(mn, ops).strip(), (mn, ops)
    assert {'vmulax', 'vmadday', 'vmaddw', 'vftoi0', 'vdiv', 'vsqrt',
            'vclipw', 'vmove', 'vmr32', 'vopmsub', 'vnop'} <= seen
    for mn, ops in (('lqc2', '$vf4, 16($s1)'), ('sqc2', '$vf9, 0($a0)'),
                    ('qmfc2', '$v0, $vf5'), ('qmtc2', '$v0, $vf5'),
                    ('cfc2', '$v0, $vi16'), ('ctc2', '$v0, $vi28')):
        assert one(mn, ops).strip(), mn
    # The accumulator chain writes vacc, not a register, and a broadcast
    # latches its component before any destination component is written.
    acc = one('vmulax.xyzw', 'ACC, $vf4, $vf8')
    assert acc.startswith('{ const u32 _bc = vf[8][0];') and 'vacc[3] =' in acc
    assert acc.count('_bc') == 5           # latched once, then read four times
    # A masked-out component still clears its MAC flags
    assert one('vmaddw.xy', '$vf9, $vf7, $vf8').count('VMCLR(') == 2
    # MIN/MAX pick a bit pattern; they must not go near VRES or the flags
    mx = one('vmaxx.xyzw', '$vf1, $vf2, $vf3')
    assert 'VMAX(' in mx and 'VRES' not in mx and 'VSTAT' not in mx
    # Writes to VF00 vanish, exactly as in the interpreter
    assert one('vadd.xyzw', '$vf0, $vf1, $vf2').count('vf[0]') == 0
    assert one('vmove.xyzw', '$vf0, $vf1') == ';'
    assert one('vdiv', '$vf4.w, $vf8.x') == 'VDIV(vf[4][3], vf[8][0]);'
    assert one('vsqrt', '$vf8.z') == 'VSQRTQ(vf[8][2]);'
    assert one('vclipw', '$vf4, $vf8') == 'VCLIP(vf[4], vf[8][3]);'
    assert one('cfc2', '$v0, $vi29') == 'r[2] = (u64)(SX32(0u));'
    try:
        one('cfc2', '$v0, $vi3')
        raise AssertionError('CFC2 of an integer VI must refuse')
    except Unliftable:
        pass
    selftest()          # jump-table recovery
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        demo()          # emitter smoke-check, then jump-table recovery
    else:
        print(lift(sys.argv[1], sys.argv[2],
                   int(sys.argv[3]) if len(sys.argv) > 3 else 0))
