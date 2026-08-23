"""An R5900 interpreter -- enough to execute real game functions.

Used to check decompilations by behaviour instead of by bytes. Byte-matching
would need Metrowerks MIPS 2.4.1 (no other compiler picks the same
instructions), so running the original code and the rewrite on the same inputs
and comparing results is the check that is actually available -- and it tests
what the code does rather than which instructions a compiler chose.

Models: the integer core, the COP1 single-precision FPU, memory backed by the
ELF image (so globals and rodata read correctly), a stack, and calls.
Delay slots are honoured -- the instruction after a branch runs before the
branch is taken, and Metrowerks fills those slots constantly.

Known divergence: the R5900 FPU is not IEEE754. It has no Inf or NaN and
flushes denormals to zero. Ordinary game math never reaches those, but a
function that deliberately probes them will not agree with this model.

usage: python emu.py <SCUS_972.05> <Function> <arg> [arg...]
"""
import math, struct, sys
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN
from disasm import Image

MD = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)
M32 = 0xffffffff
M64 = 0xffffffffffffffff
M128 = (1 << 128) - 1
STACK_TOP = 0x01f00000          # well clear of the 0x00100000 text/data image
DONE = 0xdead0000               # sentinel return address


def sx32(v):
    """MIPS64 sign-extends every 32-bit result into the 64-bit register.

    Without this, `lui 0xffff; ori 0xffff` yields 0x00000000_ffffffff instead
    of 0xffffffff_ffffffff, so a -1 sentinel never compares equal and the
    SIMD string routines loop forever.
    """
    v &= M32
    return (v - (1 << 32) if v & 0x80000000 else v) & M64


def _fpkey(b):
    """Ordering key for max.s/min.s, which compare raw bit patterns.

    Float bit patterns order correctly as unsigned for positives and in
    reverse for negatives, so negate the magnitude when the sign bit is set.
    Doing it on bits (not via float) keeps +0 / -0 distinct, as the hardware
    does.
    """
    return -(b & 0x7fffffff) if b & 0x80000000 else (b & 0x7fffffff)


def s64(v):
    """Signed view of a full 64-bit register."""
    v &= M64
    return v - (1 << 64) if v & (1 << 63) else v


def s32(v):
    v &= M32
    return v - (1 << 32) if v & 0x80000000 else v


FLT_MAX = 3.4028234663852886e+38


def _rtz(x):
    """Round a Python float to single precision toward zero.

    The EE FPU's rounding mode is fixed at chop. struct.pack rounds to
    nearest-even, which differs by one ulp on roughly half of all operations.
    """
    try:
        y = struct.unpack('<f', struct.pack('<f', x))[0]
    except OverflowError:
        return x                                   # f2b saturates instead
    if abs(y) > abs(x):                            # rounded away from zero
        b = struct.unpack('<I', struct.pack('<f', y))[0] - 1
        y = struct.unpack('<f', struct.pack('<I', b))[0]
    return y


def f2b(x):
    """float -> raw u32 bits: chop, saturate at +/-FLT_MAX, flush to zero."""
    try:
        b = struct.unpack('<I', struct.pack('<f', _rtz(x)))[0]
    except OverflowError:
        return 0x7f7fffff | (0x80000000 if x < 0 else 0)
    return (b & 0x80000000) if not b & 0x7f800000 else b      # FTZ


def b2f(b):
    """raw u32 bits -> float, as the arithmetic units read them.

    Denormals-are-zero, and the exponent-255 patterns the EE can never itself
    produce read as +/-FLT_MAX. Bit moves (mov.s/abs.s/neg.s/lwc1/swc1) must
    NOT go through here -- they use the raw register value directly.
    """
    b &= M32
    e = b & 0x7f800000
    if e == 0:
        return -0.0 if b & 0x80000000 else 0.0
    if e == 0x7f800000:
        return -FLT_MAX if b & 0x80000000 else FLT_MAX
    return struct.unpack('<f', struct.pack('<I', b))[0]


class Unsupported(Exception):
    pass


REGS = ['$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3',
        '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7',
        '$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7',
        '$t8', '$t9', '$k0', '$k1', '$gp', '$sp', '$fp', '$ra']


# The MMI sub-opcode tables: op 28 picks a group by its funct field, and the
# group member by bits 10:6. Only the members this binary actually contains
# are listed -- the rest of the (large) MMI spec is dead weight here.
#   0x08 MMI0   0x28 MMI1   0x09 MMI2   0x29 MMI3
MMI_SUB = {
    (0x08, 0x01): 'psubw',  (0x08, 0x04): 'paddh',  (0x08, 0x06): 'pcgth',
    (0x08, 0x07): 'pmaxh',  (0x08, 0x09): 'psubb',  (0x08, 0x12): 'pextlw',
    (0x08, 0x1a): 'pextlb', (0x08, 0x1b): 'ppacb',
    (0x28, 0x07): 'pminh',  (0x28, 0x12): 'pextuw', (0x28, 0x18): 'paddub',
    (0x28, 0x1a): 'pextub', (0x28, 0x1b): 'qfsrv',
    (0x09, 0x0e): 'pcpyld', (0x09, 0x12): 'pand',   (0x09, 0x13): 'pxor',
    (0x29, 0x0e): 'pcpyud', (0x29, 0x12): 'por',    (0x29, 0x13): 'pnor',
    (0x29, 0x1b): 'pcpyh',
}
# Parallel halfword shifts take the amount from bits 9:6 instead of a sub-op.
MMI_SHIFT = {0x34: 'psllh', 0x36: 'psrlh', 0x37: 'psrah'}


def _split(v, w):
    """A 128-bit value as its 128/w elements, least significant first."""
    return [(v >> (w * i)) & ((1 << w) - 1) for i in range(128 // w)]


def _join(es, w):
    v = 0
    for i, e in enumerate(es):
        v |= (e & ((1 << w) - 1)) << (w * i)
    return v


def _sx(e, w):
    return e - (1 << w) if e >> (w - 1) else e


# Element-wise parallel ops: mnemonic -> (element width, per-element rule).
# A width of 128 is the whole register in one element, which is exactly what
# the bitwise ones want.
PAR = {
    'paddh':  (16, lambda a, b, w: a + b),
    'psubw':  (32, lambda a, b, w: a - b),
    'psubb':  (8,  lambda a, b, w: a - b),
    'pcgth':  (16, lambda a, b, w: (1 << w) - 1 if _sx(a, w) > _sx(b, w) else 0),
    'pmaxh':  (16, lambda a, b, w: a if _sx(a, w) >= _sx(b, w) else b),
    'pminh':  (16, lambda a, b, w: a if _sx(a, w) <= _sx(b, w) else b),
    'paddub': (8,  lambda a, b, w: min(a + b, 255)),      # unsigned saturating
    'pand':   (128, lambda a, b, w: a & b),
    'por':    (128, lambda a, b, w: a | b),
    'pxor':   (128, lambda a, b, w: a ^ b),
    'pnor':   (128, lambda a, b, w: ~(a | b)),
}


# ---- VU0 macro mode --------------------------------------------------
# The R5900 can drive VU0's FMAC straight from its own instruction stream.
# Encoding: op 18 (COP2) with bit 25 set,
#   31..26  25  24..21   20..16  15..11  10..6  5..0
#   010010   1   dest      ft      fs      fd   funct
# `dest` is the write mask, one bit per component in the order x,y,z,w.
# funct 0x3c..0x3f escape to a second table indexed by
# (bits 10:6) << 2 | (funct & 3), which is why fd is not a register there.
#
# Only the operations this ROM actually contains are listed. Everything
# else -- VCALLMS, the VI integer unit, the VU-memory loads/stores and the
# random-number unit -- is left undecoded on purpose, so a function using
# one is reported unliftable instead of quietly mismodelled.
VU_S1, VU_S2, VU_FM = {}, {}, {}
for _i, _bc in enumerate('xyzw'):
    for _o, _b in ((0x00, 'add'), (0x04, 'sub'), (0x08, 'madd'),
                   (0x0c, 'msub'), (0x10, 'max'), (0x14, 'mini'),
                   (0x18, 'mul')):
        VU_S1[_o + _i] = _b + _bc
    for _o, _b in ((0x00, 'adda'), (0x04, 'suba'), (0x08, 'madda'),
                   (0x0c, 'msuba'), (0x18, 'mula')):
        VU_S2[_o + _i] = _b + _bc
for _i, _s in enumerate(('0', '4', '12', '15')):
    VU_S2[0x10 + _i] = 'itof' + _s
    VU_S2[0x14 + _i] = 'ftoi' + _s
VU_S1.update({0x1c: 'mulq', 0x1d: 'maxi', 0x1e: 'muli', 0x1f: 'minii',
              0x20: 'addq', 0x21: 'maddq', 0x22: 'addi', 0x23: 'maddi',
              0x24: 'subq', 0x25: 'msubq', 0x26: 'subi', 0x27: 'msubi',
              0x28: 'add', 0x29: 'madd', 0x2a: 'mul', 0x2b: 'max',
              0x2c: 'sub', 0x2d: 'msub', 0x2e: 'opmsub', 0x2f: 'mini'})
VU_S2.update({0x1c: 'mulaq', 0x1e: 'mulai', 0x1f: 'clipw',
              0x20: 'addaq', 0x21: 'maddaq', 0x22: 'addai', 0x23: 'maddai',
              0x24: 'subaq', 0x25: 'msubaq', 0x26: 'subai', 0x27: 'msubai',
              0x28: 'adda', 0x29: 'madda', 0x2a: 'mula',
              0x2c: 'suba', 0x2d: 'msuba', 0x2e: 'opmula', 0x2f: 'nop',
              0x30: 'move', 0x31: 'mr32',
              0x38: 'div', 0x39: 'sqrt', 0x3b: 'waitq'})

# The FMAC ops are one operation over three source shapes, so they share a
# single executor. name -> (operation, 'f' = write VF[fd] / 'a' = write ACC,
# second operand: one broadcast component, Q, I, or elementwise 'v').
for _op in ('add', 'sub', 'mul', 'madd', 'msub', 'max', 'mini'):
    for _dst in ('', 'a'):
        for _src in ('x', 'y', 'z', 'w', 'q', 'i', ''):
            VU_FM[_op + _dst + _src] = (_op, _dst or 'f', _src or 'v')

VU_2P128 = 2.0 ** 128           # first magnitude the VU exponent cannot hold


def vu_res(x):
    """A VU FMAC result -> (raw bits, MAC nibble).

    The VU float unit has no NaN or infinity: the exponent saturates at
    +/-FLT_MAX, denormal results flush to a signed zero, and rounding is
    toward zero. That is the same arithmetic the EE FPU uses (f2b), but the
    VU additionally records four flags per component, which is what the
    nibble carries: 8 overflow, 4 underflow, 2 sign, 1 zero.
    """
    sgn = 0x80000000 if (x < 0 or (x == 0 and math.copysign(1, x) < 0)) else 0
    if abs(x) >= VU_2P128:
        return sgn | 0x7f7fffff, 8 | (sgn >> 30)
    try:
        raw = struct.unpack('<I', struct.pack('<f', _rtz(x)))[0]
    except OverflowError:                       # inside the FLT_MAX..2^128 gap
        return sgn | 0x7f7fffff, sgn >> 30
    n = (raw >> 30) & 2
    if raw & 0x7f800000:
        return raw, n
    # Exponent zero: a denormal underflowed (and is flushed), a true zero
    # did not. Both report zero; only the denormal reports underflow.
    return raw & 0x80000000, n | (5 if raw & 0x7fffff else 1)


def vu_max(a, b):
    """Larger of two VU floats, compared as bit patterns so that denormals
    and the exponent-255 patterns order the way the hardware orders them.
    Ties keep fs, and -0.0 counts as smaller than +0.0."""
    ia, ib = s32(a), s32(b)
    return (a if ia <= ib else b) if ia < 0 and ib < 0 else (a if ia >= ib else b)


def vu_min(a, b):
    ia, ib = s32(a), s32(b)
    return (a if ia >= ib else b) if ia < 0 and ib < 0 else (a if ia <= ib else b)


def vu_ftoi(b, n):
    """float -> fixed point with n fraction bits, truncated toward zero and
    clamped to the signed 32-bit range. The input is used raw, not through
    b2f: FTOI is a conversion, not an arithmetic operand."""
    f = struct.unpack('<f', struct.pack('<I', b))[0]
    if n:
        try:
            f = struct.unpack('<f', struct.pack('<f', f * (2.0 ** n)))[0]
            b = struct.unpack('<I', struct.pack('<f', f))[0]
        except (OverflowError, ValueError):
            b = 0x7f800000 | (b & 0x80000000)
    if (b & 0x7f800000) >= 0x4f000000:          # |value| >= 2^31, or not finite
        return 0x80000000 if b & 0x80000000 else 0x7fffffff
    return int(f) & M32


def vu_itof(b, n):
    """The inverse: a signed 32-bit fixed-point value with n fraction bits."""
    return f2b(_rtz(float(s32(b))) * (2.0 ** -n))


def _vu_dest(rs):
    return ''.join(c for i, c in enumerate('xyzw') if rs & (8 >> i))


def _vu_decode(w, rs):
    """The COP2 macro-mode word -> (mnemonic, operands)."""
    fn = w & 0x3f
    base = (VU_S2.get((((w >> 6) & 0x1f) << 2) | (w & 3)) if fn >= 0x3c
            else VU_S1.get(fn))
    if base is None:
        raise Unsupported(f'unmodelled VU0 macro op {w:#010x}')
    ft, fs, fd, d = (w >> 16) & 31, (w >> 11) & 31, (w >> 6) & 31, _vu_dest(rs)
    if base in VU_FM:
        dst = 'ACC' if VU_FM[base][1] == 'a' else f'$vf{fd}'
        return f'v{base}.{d}', f'{dst}, $vf{fs}, $vf{ft}'
    if base in ('nop', 'waitq'):
        return 'v' + base, ''
    if base in ('move', 'mr32') or base[:4] in ('ftoi', 'itof'):
        return f'v{base}.{d}', f'$vf{ft}, $vf{fs}'      # destination is ft
    if base == 'clipw':
        return 'vclipw', f'$vf{fs}, $vf{ft}'
    if base == 'opmula':
        return 'vopmula', f'ACC, $vf{fs}, $vf{ft}'
    if base == 'opmsub':
        return 'vopmsub', f'$vf{fd}, $vf{fs}, $vf{ft}'
    # DIV/SQRT take one component of each source; the field that is a write
    # mask elsewhere selects them here (bits 24:23 for ft, 22:21 for fs).
    fsf, ftf = 'xyzw'[(w >> 21) & 3], 'xyzw'[(w >> 23) & 3]
    if base == 'div':
        return 'vdiv', f'$vf{fs}.{fsf}, $vf{ft}.{ftf}'
    return 'vsqrt', f'$vf{ft}.{ftf}'


def decode_mmi(word):
    """Decode the R5900 encodings capstone gets wrong, else None.

    The Emotion Engine adds opcodes that plain MIPS64 does not have, and
    capstone either rejects them or reads them as unrelated DSP-ASE
    instructions:

      op 30/31  lq/sq, the 128-bit load/store Metrowerks puts in nearly every
                prologue -- misread as `ext` / `addu.qb` / `dpa.w.ph`.
      op 0      three-operand `mult rd, rs, rt` (standard MIPS mult takes two
                operands and writes only HI/LO) -- rejected outright.
      op 28     the MMI unit: the second accumulator pipeline (MULT1, MFLO1,
                ...), MADD, and the 128-bit parallel SIMD ops (see MMI_SUB).
                capstone reads the three-operand MADD as a DSP accumulator
                write and rejects the parallel ops outright.
      op 1      MTSAB/MTSAH, which set the shift-amount register QFSRV reads.
    """
    w, = struct.unpack('<I', word)
    op, fn = w >> 26, w & 0x3f
    rs, rt, rd, sa = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31, (w >> 6) & 31
    if op == 1 and rt in (0x18, 0x19):                  # REGIMM -> MTSAB/MTSAH
        return (('mtsab' if rt == 0x18 else 'mtsah'), f'{REGS[rs]}, {w & 0xffff}')
    if op in (30, 31, 54, 62):
        off = w & 0xffff
        if off & 0x8000:
            off -= 0x10000
        nm = {30: 'lq', 31: 'sq', 54: 'lqc2', 62: 'sqc2'}[op]
        reg = f'$vf{rt}' if op > 31 else REGS[rt]
        return (nm, f'{reg}, {off}({REGS[rs]})')
    if op == 18:                                    # COP2 -- VU0 macro mode
        if rs & 0x10:
            return _vu_decode(w, rs)
        nm = {1: 'qmfc2', 2: 'cfc2', 5: 'qmtc2', 6: 'ctc2'}.get(rs)
        if nm is None:
            raise Unsupported(f'unmodelled COP2 op {w:#010x}')
        return (nm, f'{REGS[rt]}, ' + (f'$vi{rd}' if nm[1] == 'c' else f'$vf{rd}'))
    if op == 17 and ((w >> 21) & 31) == 16:            # COP1, fmt = S
        # The EE adds an FPU accumulator and min/max that plain MIPS lacks;
        # capstone rejects all of these encodings. ft = 20:16, fs = 15:11,
        # fd = 10:6. sqrt.s is the odd one: its operand is in ft, not fs.
        ft, fs, fd = (w >> 16) & 31, (w >> 11) & 31, (w >> 6) & 31
        acc2 = {0x18: 'adda.s', 0x19: 'suba.s', 0x1a: 'mula.s',
                0x1e: 'madda.s', 0x1f: 'msuba.s'}
        acc3 = {0x1c: 'madd.s', 0x1d: 'msub.s', 0x28: 'max.s', 0x29: 'min.s'}
        if fn in acc2:
            return (acc2[fn], f'$f{fs}, $f{ft}')
        if fn in acc3:
            return (acc3[fn], f'$f{fd}, $f{fs}, $f{ft}')
        if fn == 0x04:
            return ('sqrt.s', f'$f{fd}, $f{ft}')
    if op == 0 and fn in (0x1a, 0x1b):                 # DIV / DIVU
        # capstone renders the two-operand form as `div $zero, rs, rt`, so a
        # positional read divides $zero by rs -- i.e. every division returned
        # 0. The EE has no rd form here; name the real operands.
        return (('div' if fn == 0x1a else 'divu'), f'{REGS[rs]}, {REGS[rt]}')
    if op == 0 and fn in (0x18, 0x19) and rd:          # 3-operand mult
        return (('mult3' if fn == 0x18 else 'multu3'),
                f'{REGS[rd]}, {REGS[rs]}, {REGS[rt]}')
    if op == 28:
        if fn in (0x18, 0x19):                          # second pipeline
            return (('mult1' if fn == 0x18 else 'multu1'),
                    f'{REGS[rd]}, {REGS[rs]}, {REGS[rt]}')
        if fn in (0x1a, 0x1b):
            return (('div1' if fn == 0x1a else 'divu1'),
                    f'{REGS[rs]}, {REGS[rt]}')
        if fn == 0x10:
            return ('mfhi1', REGS[rd])
        if fn == 0x12:
            return ('mflo1', REGS[rd])
        if fn == 0x11:
            return ('mthi1', REGS[rs])
        if fn == 0x13:
            return ('mtlo1', REGS[rs])
        if fn in (0x00, 0x01):                          # MADD / MADDU
            return (('madd' if fn == 0x00 else 'maddu'),
                    f'{REGS[rd]}, {REGS[rs]}, {REGS[rt]}')
        if fn in MMI_SHIFT:                             # PSLLH / PSRLH / PSRAH
            return (MMI_SHIFT[fn], f'{REGS[rd]}, {REGS[rt]}, {sa & 15}')
        if (fn, sa) in MMI_SUB:
            return (MMI_SUB[(fn, sa)], f'{REGS[rd]}, {REGS[rs]}, {REGS[rt]}')
    return None


class Machine:
    def __init__(self, img):
        self.img = img
        self.mem = {}                       # sparse byte overlay over the ELF
        self.icache = {}
        self.gp = self._gp()

    def _gp(self):
        """ri_gp_value from .reginfo -- makes $gp-relative globals resolve."""
        try:
            sec = self.img.S['.reginfo']
            blob = self.img.d[sec[4]:sec[4] + sec[5]]
            return struct.unpack_from('<I', blob, 20)[0]
        except Exception:
            return 0

    # ---- memory -------------------------------------------------------
    def rb(self, a):
        a &= M32
        if a in self.mem:
            return self.mem[a]
        # Only read the image where it is actually mapped. Image.read computes
        # off + (a - base); for a below base that is a negative index, and
        # Python would slice from the END of the file and hand back garbage.
        if self.img.base <= a < self.img.base + self.img.size:
            b = self.img.read(a, 1)
            if b:
                return b[0]
        return 0

    def wb(self, a, v):
        self.mem[a & M32] = v & 0xff

    def load(self, a, n, signed=False):
        v = 0
        for i in range(n):                  # little-endian
            v |= self.rb(a + i) << (8 * i)
        if signed and v & (1 << (8 * n - 1)):
            v -= 1 << (8 * n)
        return v

    def store(self, a, n, v):
        for i in range(n):
            self.wb(a + i, (v >> (8 * i)) & 0xff)

    # ---- instruction fetch --------------------------------------------
    def ins(self, pc):
        got = self.icache.get(pc)
        if got is None:
            word = self.img.read(pc, 4)
            if len(word) < 4:
                raise Unsupported(f'no code at {pc:#x}')
            got = decode_mmi(word) or self._cs(word, pc)
            self.icache[pc] = got
        return got

    def _cs(self, word, pc):
        d = list(MD.disasm(word, pc))
        if d:
            return (d[0].mnemonic, d[0].op_str)
        w, = struct.unpack('<I', word)
        # COP0 (op 16) -- ei/di/tlb ops. They touch privileged state only, so
        # for user-level behaviour they are no-ops. capstone rejects some of
        # the R5900 encodings outright (e.g. ei = 0x42000038).
        if (w >> 26) == 16:
            return ('cop0nop', '')
        raise Unsupported(f'undecodable word at {pc:#x}')


def _lwl(old, m, a, w):
    """Load the bytes from the aligned word start up to `a` into the high end.

    Little-endian: mem[a] lands in the most significant byte, and everything
    below the filled region keeps its previous contents.
    """
    v = old
    for i in range((a & (w - 1)) + 1):
        sh = 8 * (w - 1 - i)
        v = (v & ~(0xff << sh)) | (m.rb(a - i) << sh)
    return v


def _lwr(old, m, a, w):
    """Load the bytes from `a` to the end of the aligned word into the low end."""
    v = old
    for i in range(w - (a & (w - 1))):
        sh = 8 * i
        v = (v & ~(0xff << sh)) | (m.rb(a + i) << sh)
    return v


def _swl(val, m, a, w):
    """Store the high bytes of `val` from the aligned word start up to `a`."""
    for i in range((a & (w - 1)) + 1):
        m.wb(a - i, (val >> (8 * (w - 1 - i))) & 0xff)


def _swr(val, m, a, w):
    """Store the low bytes of `val` from `a` to the end of the aligned word."""
    for i in range(w - (a & (w - 1))):
        m.wb(a + i, (val >> (8 * i)) & 0xff)


LOAD_N = {'lb': (1, 1), 'lbu': (1, 0), 'lh': (2, 1), 'lhu': (2, 0),
          'lw': (4, 1), 'lwu': (4, 0), 'ld': (8, 0)}
STORE_N = {'sb': 1, 'sh': 2, 'sw': 4, 'sd': 8}
FBIN = {'add.s': lambda a, b: a + b, 'sub.s': lambda a, b: a - b,
        'mul.s': lambda a, b: a * b}
# The R5900 has no NaN, so the ordered/unordered/signalling spellings all
# collapse to the same three comparisons here.
FCMP = {}
for _p in ('', 'u', 'o', 'ng', 'sf', 'ns'):
    FCMP[f'c.{_p}eq.s'] = lambda a, b: a == b
    FCMP[f'c.{_p}lt.s'] = lambda a, b: a < b
    FCMP[f'c.{_p}le.s'] = lambda a, b: a <= b
FCMP['c.une.s'] = lambda a, b: a != b
FCMP['c.olt.s'] = lambda a, b: a < b
FCMP['c.ole.s'] = lambda a, b: a <= b
COND = {
    'beqz': lambda a, b: a == 0,      'bnez': lambda a, b: a != 0,
    'beq':  lambda a, b: a == b,      'bne':  lambda a, b: a != b,
    'blez': lambda a, b: s64(a) <= 0, 'bgtz': lambda a, b: s64(a) > 0,
    'bltz': lambda a, b: s64(a) < 0,  'bgez': lambda a, b: s64(a) >= 0,
}


class Emu:
    def __init__(self, img, machine=None):
        self.img = img
        self.m = machine or Machine(img)
        self.r = {}
        self.rhi = {}          # upper 64 bits, for lq/sq
        self.f = {}
        self.fcc = False
        self.hi = self.lo = 0
        self.hi1 = self.lo1 = 0        # R5900 second accumulator
        self.acc = 0                   # EE FPU accumulator (ACC)
        self.indirect = None           # set() -> record jalr targets
        self.sa = 0                    # shift-amount register (MTSAB -> QFSRV)
        self.vu_reset()

    # ---- VU0 ----------------------------------------------------------
    def vu_reset(self):
        self.vf = [[0, 0, 0, 0] for _ in range(32)]
        self.vf[0][3] = 0x3f800000     # VF00 is hardwired to (0, 0, 0, 1.0)
        self.vacc = [0, 0, 0, 0]
        self.vi = [0] * 32             # only the control registers are used
        self.vq = 0
        self.vmac = 0

    def _vmac(self, i, x):
        """Write one component's worth of MAC flags. -> the result bits."""
        b, n = vu_res(x)
        sh = 3 - i
        self.vmac = (self.vmac & ~(0x1111 << sh)) | sum(
            ((n >> k) & 1) << (4 * k + sh) for k in range(4))
        return b

    def _vstat(self):
        """VI16 keeps the current flags in bits 3:0 and sticky copies in 9:6;
        the D/I bits DIV owns (5:4, 11:10) are left alone."""
        n = sum(bool(self.vmac & (0xf << (4 * k))) << k for k in range(4))
        self.vi[16] = (self.vi[16] & 0xff0) | n | (n << 6)

    def _vdiv(self, q, flag):
        self.vq = q
        self.vi[16] = (self.vi[16] & 0xfcf) | flag

    # ---- registers ----------------------------------------------------
    def get(self, n):
        if n == '$zero':
            return 0
        if n == '$gp':
            return self.m.gp
        return self.r.get(n, 0) & M64

    def g32(self, n):
        return self.get(n) & M32

    def set(self, n, v):
        if n not in ('$zero',):
            self.r[n] = v & M64

    def q(self, n):
        """The whole 128-bit register: rhi (bits 127:64) over r (bits 63:0)."""
        return ((self.rhi.get(n, 0) & M64) << 64) | self.get(n)

    def qset(self, n, v):
        if n == '$zero':
            return
        self.r[n] = v & M64
        self.rhi[n] = (v >> 64) & M64

    def fg(self, n):
        return self.f.get(n, 0) & M32

    def fs(self, n, bits):
        self.f[n] = bits & M32

    # ---- one instruction ----------------------------------------------
    def step(self, mn, ops):
        p = [x.strip() for x in ops.split(',')] if ops else []
        if mn in ('nop', 'ehb', 'ssnop', 'sync', 'cache', 'break',
                  'cop0nop', 'ei', 'di', 'mtc0'):
            return
        if mn == 'mfc0':                 # privileged; reads as 0 here
            self.set(p[0], 0); return
        if mn[0] == 'v' or mn in ('lqc2', 'sqc2', 'qmfc2', 'qmtc2',
                                  'cfc2', 'ctc2'):
            return self.vstep(mn, p)

        # 128-bit load/store: the upper half is tracked so that a prologue's
        # sq and its matching epilogue lq round-trip exactly.
        if mn in ('lq', 'sq'):
            reg, addr = p[0], p[1]
            o, b = addr.split('(')
            ea = (self.get(b.rstrip(')')) + (int(o, 0) if o.strip() else 0)) & ~15
            if mn == 'sq':
                self.m.store(ea, 8, self.get(reg))
                self.m.store(ea + 8, 8, self.rhi.get(reg, 0))
            else:
                self.set(reg, self.m.load(ea, 8))
                self.rhi[reg] = self.m.load(ea + 8, 8)
            return

        # unaligned loads: lwl/lwr (and the 64-bit ldl/ldr) merge a partial
        # word into the existing register rather than replacing it
        if mn in ('lwl', 'lwr', 'ldl', 'ldr'):
            reg, addr = p[0], p[1]
            o_, b_ = (addr.split('(') + [''])[:2]
            ea = (self.get(b_.rstrip(')')) + (int(o_, 0) if o_.strip() else 0)) & M32
            wd = 4 if mn.startswith('lw') else 8
            cur = self.get(reg) & ((1 << (8 * wd)) - 1)
            v = (_lwl if mn.endswith('l') else _lwr)(cur, self.m, ea, wd)
            self.set(reg, sx32(v) if wd == 4 else v)
            return

        if mn in ('swl', 'swr', 'sdl', 'sdr'):
            reg, addr = p[0], p[1]
            o_, b_ = (addr.split('(') + [''])[:2]
            ea = (self.get(b_.rstrip(')')) + (int(o_, 0) if o_.strip() else 0)) & M32
            wd = 4 if mn.startswith('sw') else 8
            (_swl if mn.endswith('l') else _swr)(self.get(reg), self.m, ea, wd)
            return

        # memory
        if mn in LOAD_N or mn in STORE_N or mn in ('lwc1', 'swc1'):
            reg, addr = p[0], p[1]
            off, base = 0, addr
            if '(' in addr:
                o, b = addr.split('(')
                off = int(o, 0) if o.strip() else 0
                base = b.rstrip(')')
            ea = (self.get(base) + off) & M32
            if mn == 'lwc1':
                self.fs(reg, self.m.load(ea, 4)); return
            if mn == 'swc1':
                self.m.store(ea, 4, self.fg(reg)); return
            if mn in LOAD_N:
                n, sg = LOAD_N[mn]
                self.set(reg, self.m.load(ea, n, bool(sg)) & M64); return
            self.m.store(ea, STORE_N[mn], self.get(reg)); return

        # FPU
        if mn in FBIN:
            self.fs(p[0], f2b(FBIN[mn](b2f(self.fg(p[1])), b2f(self.fg(p[2]))))); return
        if mn == 'div.s':
            n, d = b2f(self.fg(p[1])), b2f(self.fg(p[2]))
            if not self.fg(p[2]) & 0x7f800000:      # zero OR denormal (DAZ)
                # No Inf on the R5900: division by zero saturates to +/-FLT_MAX
                sign = (self.fg(p[1]) ^ self.fg(p[2])) & 0x80000000
                self.fs(p[0], 0x7f7fffff | sign)
            else:
                self.fs(p[0], f2b(n / d))
            return
        if mn == 'sqrt.s':
            b = self.fg(p[1])
            if not b & 0x7f800000:              # zero or denormal -> +/-0
                self.fs(p[0], b & 0x80000000); return
            self.fs(p[0], f2b(abs(b2f(b)) ** 0.5)); return   # EE uses |x|
        if mn in ('adda.s', 'suba.s', 'mula.s'):
            x, y = b2f(self.fg(p[0])), b2f(self.fg(p[1]))
            self.acc = f2b({'adda.s': x + y, 'suba.s': x - y,
                            'mula.s': x * y}[mn]); return
        if mn in ('madda.s', 'msuba.s'):
            prod = f2b(b2f(self.fg(p[0])) * b2f(self.fg(p[1])))
            a = b2f(self.acc)
            self.acc = f2b(a + b2f(prod) if mn == 'madda.s' else a - b2f(prod))
            return
        if mn in ('madd.s', 'msub.s'):
            # Not fused: the EE rounds the product, then rounds the sum.
            prod = f2b(b2f(self.fg(p[1])) * b2f(self.fg(p[2])))
            a = b2f(self.acc)
            self.fs(p[0], f2b(a + b2f(prod) if mn == 'madd.s' else a - b2f(prod)))
            return
        if mn in ('max.s', 'min.s'):
            x, y = self.fg(p[1]), self.fg(p[2])
            kx, ky = _fpkey(x), _fpkey(y)
            self.fs(p[0], (x if kx > ky else y) if mn == 'max.s'
                    else (x if kx < ky else y)); return
        if mn == 'abs.s':
            self.fs(p[0], self.fg(p[1]) & 0x7fffffff); return
        if mn == 'neg.s':
            self.fs(p[0], self.fg(p[1]) ^ 0x80000000); return
        if mn == 'mov.s':
            self.fs(p[0], self.fg(p[1])); return
        if mn == 'cvt.s.w':
            self.fs(p[0], f2b(float(s32(self.fg(p[1]))))); return
        if mn in ('cvt.w.s', 'trunc.w.s'):
            b = self.fg(p[1])
            if (b & 0x7f800000) <= 0x4e800000:      # |x| < 2^31: truncate
                self.fs(p[0], int(b2f(b)) & M32)
            else:                                   # else saturate, per HW
                self.fs(p[0], 0x80000000 if b & 0x80000000 else 0x7fffffff)
            return
        if mn == 'mtc1':
            self.fs(p[1], self.g32(p[0])); return
        if mn == 'mfc1':
            self.set(p[0], s32(self.fg(p[1])) & M64); return
        if mn in FCMP:
            self.fcc = FCMP[mn](b2f(self.fg(p[0])), b2f(self.fg(p[1]))); return

        # integer
        if mn == 'move':
            self.set(p[0], self.get(p[1])); return
        if mn == 'li':
            self.set(p[0], int(p[1], 0)); return
        if mn in ('addiu', 'addi'):
            self.set(p[0], sx32(self.get(p[1]) + int(p[2], 0))); return
        if mn in ('daddiu', 'daddi'):          # true 64-bit: no truncation
            self.set(p[0], self.get(p[1]) + int(p[2], 0)); return
        if mn in ('addu', 'add'):
            self.set(p[0], sx32(self.get(p[1]) + self.get(p[2]))); return
        if mn in ('daddu', 'dadd'):
            self.set(p[0], self.get(p[1]) + self.get(p[2])); return
        if mn in ('subu', 'sub'):
            self.set(p[0], sx32(self.get(p[1]) - self.get(p[2]))); return
        if mn in ('dsubu', 'dsub'):
            self.set(p[0], self.get(p[1]) - self.get(p[2])); return
        if mn == 'negu':
            self.set(p[0], sx32(-self.get(p[1]))); return
        if mn == 'not':
            self.set(p[0], ~self.get(p[1])); return
        # MIPS III: the set-less-than family compares full 64-bit registers.
        # Truncating to 32 silently mis-orders any value wider than a word,
        # which is most of the software 64-bit arithmetic in this ROM.
        if mn == 'sltiu':          # imm sign-extends to 64, compared unsigned
            self.set(p[0], 1 if self.get(p[1]) < (int(p[2], 0) & M64) else 0); return
        if mn == 'slti':
            self.set(p[0], 1 if s64(self.get(p[1])) < int(p[2], 0) else 0); return
        if mn == 'sltu':
            self.set(p[0], 1 if self.get(p[1]) < self.get(p[2]) else 0); return
        if mn == 'slt':
            self.set(p[0], 1 if s64(self.get(p[1])) < s64(self.get(p[2])) else 0); return
        if mn == 'andi':
            self.set(p[0], self.get(p[1]) & int(p[2], 0)); return
        if mn == 'ori':
            self.set(p[0], self.get(p[1]) | int(p[2], 0)); return
        if mn == 'xori':
            self.set(p[0], self.get(p[1]) ^ int(p[2], 0)); return
        if mn in ('and', 'or', 'xor', 'nor'):
            a, b = self.get(p[1]), self.get(p[2])
            v = {'and': a & b, 'or': a | b, 'xor': a ^ b, 'nor': ~(a | b)}[mn]
            self.set(p[0], v); return
        if mn == 'lui':
            self.set(p[0], sx32(int(p[1], 0) << 16)); return
        if mn in ('sll', 'srl', 'sra', 'sllv', 'srlv', 'srav'):
            sh = int(p[2], 0) & 31 if mn in ('sll', 'srl', 'sra') else self.g32(p[2]) & 31
            v = self.g32(p[1])
            v = (v << sh) if mn.startswith('sll') else (
                (v >> sh) if mn.startswith('srl') else (s32(v) >> sh))
            self.set(p[0], s32(v & M32) & M64); return
        if mn in ('dsllv', 'dsrlv', 'dsrav'):
            sh = self.get(p[2]) & 63
            v = self.get(p[1])
            if mn == 'dsllv':
                self.set(p[0], v << sh)
            elif mn == 'dsrlv':
                self.set(p[0], v >> sh)
            else:
                sv = v - (1 << 64) if v & (1 << 63) else v
                self.set(p[0], sv >> sh)
            return
        if mn in ('dsll', 'dsll32', 'dsrl', 'dsrl32', 'dsra', 'dsra32'):
            sh = int(p[2], 0) + (32 if mn.endswith('32') else 0)
            v = self.get(p[1])
            if mn.startswith('dsll'):
                self.set(p[0], v << sh)
            elif mn.startswith('dsrl'):
                self.set(p[0], v >> sh)
            else:
                sv = v - (1 << 64) if v & (1 << 63) else v
                self.set(p[0], sv >> sh)
            return
        if mn in ('mult', 'multu'):
            a, b = self.g32(p[0]), self.g32(p[1])
            if mn == 'mult':
                a, b = s32(a), s32(b)
            r = a * b
            self.lo, self.hi = s32(r & M32), s32((r >> 32) & M32)
            return
        if mn in ('mul', 'mulu'):
            self.set(p[0], s32(self.g32(p[1]) * self.g32(p[2]) & M32) & M64); return
        if mn in ('div', 'divu'):
            a, b = self.g32(p[0]), self.g32(p[1])
            if mn == 'div':
                a, b = s32(a), s32(b)
            if b == 0:
                # Real MIPS does not trap here; LO/HI are simply unpredictable
                # and the compiler's following `break` guards the case. Leave
                # them unchanged, which is what the lifted C++ also does.
                return
            q = abs(a) // abs(b)
            self.lo = -q if (a < 0) != (b < 0) else q
            self.hi = a - self.lo * b
            return
        if mn in ('mult3', 'multu3', 'mult1', 'multu1'):
            a, b = self.g32(p[1]), self.g32(p[2])
            if mn in ('mult3', 'mult1'):
                a, b = s32(a), s32(b)
            r_ = a * b
            lo_, hi_ = s32(r_ & M32), s32((r_ >> 32) & M32)
            if mn.endswith('1'):
                self.lo1, self.hi1 = lo_, hi_
            else:
                self.lo, self.hi = lo_, hi_
            self.set(p[0], lo_)                 # the 3-operand form writes rd
            return
        if mn in ('div1', 'divu1'):
            a, b = self.g32(p[0]), self.g32(p[1])
            if mn == 'div1':
                a, b = s32(a), s32(b)
            if b == 0:
                return                      # as above: no trap, LO1/HI1 stale
            q = abs(a) // abs(b)
            self.lo1 = -q if (a < 0) != (b < 0) else q
            self.hi1 = a - self.lo1 * b
            return
        if mn == 'mfhi1':
            self.set(p[0], self.hi1); return
        if mn == 'mflo1':
            self.set(p[0], self.lo1); return
        if mn == 'mthi1':
            self.hi1 = self.get(p[0]); return
        if mn == 'mtlo1':
            self.lo1 = self.get(p[0]); return
        if mn in ('madd', 'maddu'):
            # HI:LO (the low 32 bits of each) accumulates the 32x32 product;
            # both halves come back sign-extended, and rd takes the new LO.
            a, b = self.g32(p[1]), self.g32(p[2])
            if mn == 'madd':
                a, b = s32(a), s32(b)
            t = (((self.hi & M32) << 32) | (self.lo & M32)) + a * b
            self.lo, self.hi = s32(t & M32), s32((t >> 32) & M32)
            self.set(p[0], self.lo)
            return

        # ---- 128-bit parallel (MMI) ops --------------------------------
        if mn in PAR:
            w, fun = PAR[mn]
            xs, ys = _split(self.q(p[1]), w), _split(self.q(p[2]), w)
            self.qset(p[0], _join([fun(x, y, w) for x, y in zip(xs, ys)], w))
            return
        if mn in MMI_SHIFT.values():            # PSLLH / PSRLH / PSRAH
            sh = int(p[2], 0) & 15
            g = {'psllh': lambda e: e << sh, 'psrlh': lambda e: e >> sh,
                 'psrah': lambda e: _sx(e, 16) >> sh}[mn]
            self.qset(p[0], _join([g(e) for e in _split(self.q(p[1]), 16)], 16))
            return
        if mn in ('pextlb', 'pextub', 'pextlw', 'pextuw'):
            # Interleave the low (or upper) half of rt and rs, rt going to the
            # even element slots.
            w = 8 if mn.endswith('b') else 32
            h = 64 // w
            base = h if mn[4] == 'u' else 0
            xs = _split(self.q(p[1]), w)[base:base + h]
            ys = _split(self.q(p[2]), w)[base:base + h]
            self.qset(p[0], _join([e for pair in zip(ys, xs) for e in pair], w))
            return
        if mn == 'ppacb':                       # low byte of each halfword
            xs, ys = _split(self.q(p[1]), 16), _split(self.q(p[2]), 16)
            self.qset(p[0], _join([e & 0xff for e in ys] +
                                  [e & 0xff for e in xs], 8))
            return
        if mn == 'pcpyld':                      # rd = rs_lo:rt_lo (128-bit)
            self.qset(p[0], (self.get(p[1]) << 64) | self.get(p[2]))
            return
        if mn == 'pcpyud':                      # rd = rt_hi:rs_hi
            self.qset(p[0], ((self.q(p[2]) >> 64) << 64) | (self.q(p[1]) >> 64))
            return
        if mn == 'pcpyh':                       # low halfword of each half, x4
            t = self.q(p[2])
            self.qset(p[0], _join([t & 0xffff] * 4 + [(t >> 64) & 0xffff] * 4, 16))
            return
        if mn in ('mtsab', 'mtsah'):
            if mn == 'mtsab':
                self.sa = ((self.get(p[0]) & 0xf) ^ (int(p[1], 0) & 0xf)) * 8
            else:
                self.sa = ((self.get(p[0]) & 0x7) ^ (int(p[1], 0) & 0x7)) * 16
            return
        if mn == 'qfsrv':                       # (rs:rt) >> SA, low 128 bits
            self.qset(p[0], (((self.q(p[1]) << 128) | self.q(p[2]))
                             >> self.sa) & M128)
            return
        if mn == 'mthi':
            self.hi = self.get(p[0]); return
        if mn == 'mtlo':
            self.lo = self.get(p[0]); return
        if mn == 'mfhi':
            self.set(p[0], self.hi); return
        if mn == 'mflo':
            self.set(p[0], self.lo); return
        if mn in ('movn', 'movz'):
            c = self.get(p[2])
            if (c != 0) if mn == 'movn' else (c == 0):
                self.set(p[0], self.get(p[1]))
            return
        if mn == 'ext':                      # only the idiom Metrowerks emits
            self.set(p[0], (self.get(p[1]) >> int(p[2], 0)) & ((1 << int(p[3], 0)) - 1))
            return
        raise Unsupported(f'{mn} {ops}')

    # ---- one VU0 macro-mode instruction --------------------------------
    def vstep(self, mn, p):
        base, _, dest = mn[1:].partition('.')

        if mn in ('vnop', 'vwaitq'):        # Q has no latency in this model
            return
        if mn in ('lqc2', 'sqc2'):
            o, b = p[1].split('(')
            ea = (self.get(b.rstrip(')')) + (int(o, 0) if o.strip() else 0)) & ~15
            n = int(p[0][3:])
            if mn == 'sqc2':
                for i in range(4):
                    self.m.store(ea + 4 * i, 4, self.vf[n][i])
            elif n:
                for i in range(4):
                    self.vf[n][i] = self.m.load(ea + 4 * i, 4)
            return
        if mn in ('qmfc2', 'qmtc2'):
            n = int(p[1][3:])
            if mn == 'qmfc2':
                v = self.vf[n]
                self.qset(p[0], sum(v[i] << (32 * i) for i in range(4)))
            elif n:
                v = self.q(p[0])
                self.vf[n] = [(v >> (32 * i)) & M32 for i in range(4)]
            return
        if mn in ('cfc2', 'ctc2'):
            n = int(p[1][3:])
            if n not in (16, 17, 18, 28, 29):
                # VI00-15 are only reachable through the VU integer unit,
                # which this ROM never uses and this model does not have.
                raise Unsupported(f'{mn} of VI{n}')
            if mn == 'cfc2':
                v = {17: self.vmac, 18: self.vi[18] & 0xffffff,
                     29: 0}.get(n, self.vi[n])       # VPU_STAT: VU0 is idle
                self.set(p[0], sx32(v))
            elif n == 28:                            # FBRST: only these stick
                self.vi[28] = self.g32(p[0]) & 0x0c0c
            elif n != 29:                            # VPU_STAT is read-only
                self.vi[n] = self.g32(p[0])
            return

        def vf(x):                          # '$vf7' or '$vf7.z' -> component
            r, _, c = x.partition('.')
            v = self.vf[int(r[3:])]
            return v['xyzw'.index(c)] if c else v

        if base in ('div', 'sqrt'):
            # The VU has no NaN and no infinity: a zero divisor saturates to
            # +/-FLT_MAX and raises D, or I when the dividend is zero too.
            # A negative square root takes the magnitude and raises I.
            t = b2f(vf(p[-1]))
            if base == 'sqrt':
                return self._vdiv(f2b(math.sqrt(abs(t))), 0x10 if t < 0 else 0)
            sbit = (vf(p[0]) ^ vf(p[1])) & 0x80000000
            f = b2f(vf(p[0]))
            if t == 0.0:
                return self._vdiv(sbit | 0x7f7fffff, 0x10 if f == 0.0 else 0x20)
            return self._vdiv(f2b(f / t), 0)
        if base == 'clipw':
            # Each of fs.x/y/z is tested against +|ft.w| and -|ft.w| and the
            # six answers are pushed into a 24-bit shift register. Read as
            # signed ints, float bit patterns put every negative below every
            # positive, so flipping the sign bit turns "below -|w|" into the
            # same comparison. A denormal |w| clips nothing above it.
            lim = vf(p[1])[3]
            lim = (lim & 0x7fffffff) if lim & 0x7f800000 else 0x007fffff
            c = 0
            for i in range(3):
                v = vf(p[0])[i]
                c |= (s32(v) > lim) << (2 * i)
                c |= (s32(v ^ 0x80000000) > lim) << (2 * i + 1)
            self.vi[18] = ((self.vi[18] << 6) | c) & 0xffffff
            return
        if base in ('move', 'mr32') or base[:4] in ('ftoi', 'itof'):
            n = int(p[0][3:])               # these write ft, not fd
            if not n:
                return
            # A source register can be the destination, so read it whole
            # first -- MR32 in particular would otherwise rotate its own
            # freshly written x back into w.
            src, out = list(vf(p[1])), self.vf[n]
            for i in range(4):
                if 'xyzw'[i] not in dest:
                    continue
                if base == 'move':
                    out[i] = src[i]
                elif base == 'mr32':                 # rotate x<-y<-z<-w<-x
                    out[i] = src[(i + 1) & 3]
                elif base[0] == 'f':
                    out[i] = vu_ftoi(src[i], int(base[4:]))
                else:
                    out[i] = vu_itof(src[i], int(base[4:]))
            return
        if base in ('opmula', 'opmsub'):
            # The cross-product pair: component i multiplies the two axes
            # that are not i, and OPMSUB subtracts that from the accumulator.
            a, b = list(vf(p[1])), list(vf(p[2]))
            n = 0 if base == 'opmula' else int(p[0][3:])
            out = self.vacc if base == 'opmula' else self.vf[n]
            for i in range(3):
                j, k = (i + 1) % 3, (i + 2) % 3
                x = b2f(f2b(b2f(a[j]) * b2f(b[k])))
                v = self._vmac(i, x if base == 'opmula'
                               else b2f(self.vacc[i]) - x)
                if base == 'opmula' or n:
                    out[i] = v
            self._vstat()
            return

        op, dsel, ssel = VU_FM[base]
        fs, ftv = vf(p[1]), vf(p[2])
        if ssel == 'v':
            snd = ftv
        else:
            bc = (self.vq if ssel == 'q' else self.vi[21] if ssel == 'i'
                  else ftv['xyzw'.index(ssel)])
            snd = [bc] * 4
        n = 0 if dsel == 'a' else int(p[0][3:])
        if op in ('max', 'mini'):
            # MIN/MAX are bit-pattern selects: no rounding, no MAC flags,
            # and a write to VF00 is dropped before anything else happens.
            if n:
                pick = vu_max if op == 'max' else vu_min
                for i in range(4):
                    if 'xyzw'[i] in dest:
                        self.vf[n][i] = pick(fs[i], snd[i])
            return
        out = self.vacc if dsel == 'a' else self.vf[n]
        for i in range(4):
            if 'xyzw'[i] not in dest:
                self.vmac &= ~(0x1111 << (3 - i))
                continue
            a, b = b2f(fs[i]), b2f(snd[i])
            if op == 'add':
                x = a + b
            elif op == 'sub':
                x = a - b
            elif op == 'mul':
                x = a * b
            else:
                # Not fused: the product becomes a VU float in its own right
                # before the accumulator is applied.
                pr = b2f(f2b(a * b))
                acc = b2f(self.vacc[i])
                x = acc + pr if op == 'madd' else acc - pr
            v = self._vmac(i, x)
            if dsel == 'a' or n:
                out[i] = v
        self._vstat()

    # ---- run ----------------------------------------------------------
    def run(self, addr, size=None, args=(), fargs=(), limit=2000000, calls=True):
        """Execute from addr until the entry frame returns. -> $v0."""
        self.r, self.rhi, self.f, self.fcc = {}, {}, {}, False
        self.hi = self.lo = self.hi1 = self.lo1 = self.sa = 0
        self.vu_reset()
        for i, v in enumerate(list(args)[:4]):
            self.set(f'$a{i}', v)
        for i, v in enumerate(list(fargs)[:4]):
            self.fs(f'$f{12 + i}', f2b(v) if isinstance(v, float) else v)
        self.set('$sp', STACK_TOP)
        self.set('$ra', DONE)
        pc, steps = addr, 0
        while steps < limit:
            steps += 1
            if pc == DONE:
                return self.g32('$v0')
            mn, ops = self.m.ins(pc)
            p = [x.strip() for x in ops.split(',')] if ops else []

            if mn in ('jr', 'jalr'):
                tgt = self.get(p[-1]) & M32
                if mn == 'jalr' and self.indirect is not None:
                    self.indirect.add(tgt)      # profiling for the lifter
                nxt = self.m.ins(pc + 4)
                if mn == 'jalr':
                    self.set('$ra', pc + 8)
                self.step(*nxt)
                pc = tgt
                continue
            if mn in ('j', 'b', 'jal', 'bal'):
                t = int(ops, 0)
                nxt = self.m.ins(pc + 4)
                if mn in ('jal', 'bal'):
                    if not calls:
                        raise Unsupported(f'call to {t:#x}')
                    self.set('$ra', pc + 8)
                self.step(*nxt)
                pc = t
                continue
            if mn in ('bc1t', 'bc1f', 'bc1tl', 'bc1fl'):
                taken = self.fcc if mn.startswith('bc1t') else not self.fcc
                nxt = self.m.ins(pc + 4)
                if taken or not mn.endswith('l'):
                    self.step(*nxt)
                pc = int(ops, 0) if taken else pc + 8
                continue
            base = mn[:-1] if (mn.endswith('l') and mn[:-1] in COND) else mn
            if base in COND:
                likely = base != mn
                t = int(p[-1], 0)
                a = self.get(p[0])
                b = self.get(p[1]) if len(p) == 3 else 0
                taken = COND[base](a, b)
                nxt = self.m.ins(pc + 4)
                if taken or not likely:
                    self.step(*nxt)
                pc = t if taken else pc + 8
                continue
            self.step(mn, ops)
            pc += 4
        raise Unsupported('step limit -- probable infinite loop')

    def retf(self):
        """The float return value, $f0, as a Python float."""
        return b2f(self.fg('$f0'))


def call(elf_or_img, func, *args):
    img = elf_or_img if isinstance(elf_or_img, Image) else Image(elf_or_img)
    _s, addr, size = img.func(func)
    return Emu(img).run(addr, size, list(args))


def demo():
    class Fake:
        S = {}
        d = b''
        def __init__(self, code): self.code = code
        def read(self, a, n): return self.code[a:a + n]
    # addiu $v0,$a0,1 ; jr $ra ; nop            -> f(x) = x + 1
    code = struct.pack('<III', 0x24820001, 0x03e00008, 0x00000000)
    e = Emu(Fake(code))
    assert e.run(0, None, [41]) == 42
    assert s32(0xffffffff) == -1 and s32(1) == 1
    assert abs(b2f(f2b(1.5)) - 1.5) < 1e-9
    # memory round-trip through the sparse overlay
    m = Machine(Fake(b''))
    m.store(0x1000, 4, 0x12345678)
    assert m.load(0x1000, 4) == 0x12345678
    assert m.load(0x1000, 1) == 0x78            # little-endian
    assert m.load(0x1002, 2, True) == 0x1234
    # capstone reads R5900 opcode 31 as DSP/SPECIAL3; it is really sq
    assert decode_mmi(struct.pack('<I', 0x7fb20020)) == ('sq', '$s2, 32($sp)')
    assert decode_mmi(struct.pack('<I', 0x7bb20020)) == ('lq', '$s2, 32($sp)')
    assert decode_mmi(struct.pack('<I', 0x24820001)) is None

    # ---- MMI: the words this ROM actually contains ---------------------
    def dec(w):
        return decode_mmi(struct.pack('<I', w))
    assert dec(0x7000cce9) == ('pnor',   '$t9, $zero, $zero')
    assert dec(0x7019cbf6) == ('psrlh',  '$t9, $t9, 15')
    assert dec(0x7019c874) == ('psllh',  '$t9, $t9, 1')
    assert dec(0x712856e8) == ('qfsrv',  '$t2, $t1, $t0')
    assert dec(0x700a4688) == ('pextlb', '$t0, $zero, $t2')
    assert dec(0x700a4ea8) == ('pextub', '$t1, $zero, $t2')
    assert dec(0x710a4108) == ('paddh',  '$t0, $t0, $t2')
    assert dec(0x714044a9) == ('por',    '$t0, $t2, $zero')
    assert dec(0x05b80000) == ('mtsab',  '$t5, 0')
    assert dec(0x70850000) == ('madd',   '$zero, $a0, $a1')   # capstone: 2-op
    assert dec(0x70851000) == ('madd',   '$v0, $a0, $a1')     # capstone: $ac2

    e = Emu(Fake(b''))
    def run1(mn, ops, **regs):
        for k, v in regs.items():
            e.qset('$' + k, v)
        e.step(mn, ops)
        return e.q('$v0')
    # 128-bit bitwise
    assert run1('pnor', '$v0, $zero, $zero') == M128
    assert run1('pand', '$v0, $a0, $a1', a0=0xff00ff00, a1=0x0f0f0f0f) == 0x0f000f00
    assert run1('pxor', '$v0, $a0, $a1', a0=3, a1=5) == 6
    assert run1('por',  '$v0, $a0, $zero', a0=(7 << 64) | 9) == (7 << 64) | 9
    # Parallel arithmetic wraps inside each element; it never carries across.
    assert run1('psubw', '$v0, $a0, $a1', a0=0, a1=1) == 0xffffffff
    assert run1('psubb', '$v0, $a0, $a1', a0=0, a1=1) == 0xff
    assert run1('paddh', '$v0, $a0, $a1', a0=0xffff, a1=1) == 0
    assert run1('paddub', '$v0, $a0, $a1', a0=0xf0, a1=0x20) == 0xff   # saturates
    assert run1('pcgth', '$v0, $a0, $a1', a0=0x0001, a1=0xffff) == 0xffff
    assert run1('pmaxh', '$v0, $a0, $a1', a0=0xffff, a1=0x0001) == 1
    assert run1('pminh', '$v0, $a0, $a1', a0=0xffff, a1=0x0001) == 0xffff
    # halfword shifts, per element
    assert run1('psrlh', '$v0, $a0, 15', a0=M128) == 0x0001000100010001 * (1 + (1 << 64))
    assert run1('psrah', '$v0, $a0, 15', a0=0x8000) == 0xffff
    assert run1('psllh', '$v0, $a0, 1',  a0=0x0001000100010001) == 0x0002000200020002
    # shuffles
    assert run1('pextlb', '$v0, $zero, $a1', a1=0x0807060504030201) == \
        0x00080007000600050004000300020001                # byte -> halfword
    assert run1('pextlw', '$v0, $a0, $a1', a0=0xaaaaaaaabbbbbbbb,
                a1=0x1111111122222222) == 0xaaaaaaaa11111111bbbbbbbb22222222
    assert run1('ppacb', '$v0, $a0, $a1', a0=0x0a0b0c0d0e0f0102,
                a1=0x1112131415161718) == (0x0b0d0f02 << 64) | 0x12141618
    assert run1('pcpyld', '$v0, $a0, $a1', a0=7, a1=9) == (7 << 64) | 9
    assert run1('pcpyud', '$v0, $a0, $a1', a0=(7 << 64) | 1,
                a1=(9 << 64) | 2) == (9 << 64) | 7
    assert run1('pcpyh', '$v0, $zero, $a1', a1=(0x1234 << 64) | 0xabcd) == \
        (0x1234123412341234 << 64) | 0xabcdabcdabcdabcd
    # QFSRV funnels (rs:rt) right by SA bits, SA coming from MTSAB
    e.step('mtsab', '$a2, 0')
    e.set('$a2', 1)
    e.step('mtsab', '$a2, 0')                     # SA = 1 byte = 8 bits
    assert e.sa == 8
    assert run1('qfsrv', '$v0, $a0, $a1', a0=0xff, a1=0) == 0xff << 120
    # MADD accumulates into HI:LO and hands the new LO to rd
    e.hi, e.lo = 0, 5
    e.qset('$a0', 3); e.qset('$a1', 7)
    e.step('madd', '$v0, $a0, $a1')
    assert (e.hi, e.lo, e.get('$v0')) == (0, 26, 26)
    e.qset('$a1', 0xffffffff)                        # -1, signed
    e.step('madd', '$v0, $a0, $a1')                  # 26 + 3*-1 = 23
    assert (e.hi, e.lo) == (0, 23)
    # ---- VU0 macro mode -------------------------------------------------
    # The words are lifted straight out of CPipe::RenderMesh at 0x243378.
    assert dec(0xda240000) == ('lqc2', '$vf4, 0($s1)')
    assert dec(0xf8890000) == ('sqc2', '$vf9, 0($a0)')
    assert dec(0x4be821bc) == ('vmulax.xyzw',  'ACC, $vf4, $vf8')
    assert dec(0x4be828bd) == ('vmadday.xyzw', 'ACC, $vf5, $vf8')
    assert dec(0x4be830be) == ('vmaddaz.xyzw', 'ACC, $vf6, $vf8')
    assert dec(0x4be83a4b) == ('vmaddw.xyzw',  '$vf9, $vf7, $vf8')
    assert dec(0x4bc4222a) == ('vmul.xyz',     '$vf8, $vf4, $vf4')
    assert dec(0x4be3197c) == ('vftoi0.xyzw',  '$vf3, $vf3')
    # VCALLMS runs a microprogram out of VU0 instruction memory, which this
    # model does not have. It must refuse, not guess.
    for bad in (0x4a000338, 0x48609800):
        try:
            dec(bad)
            raise AssertionError(f'{bad:#x} should be unmodelled')
        except Unsupported:
            pass
    # Every FMAC name the tables can produce must reach the shared executor.
    for _t in (VU_S1, VU_S2):
        for _b in _t.values():
            assert _b in VU_FM or _b in (
                'nop', 'waitq', 'move', 'mr32', 'clipw', 'div', 'sqrt',
                'opmula', 'opmsub') or _b[:4] in ('ftoi', 'itof'), _b

    # The VU float unit saturates instead of producing Inf, flushes denormal
    # results to a signed zero, and reports zero/sign/underflow/overflow.
    assert vu_res(1.0) == (0x3f800000, 0)
    assert vu_res(0.0) == (0, 1) and vu_res(-0.0) == (0x80000000, 3)
    assert vu_res(1e40) == (0x7f7fffff, 8)          # no +Inf
    assert vu_res(-1e40) == (0xff7fffff, 10)
    assert vu_res(1e-40) == (0, 5)                  # denormal: flushed, U set
    # Fixed-point conversions truncate toward zero and clamp at the int32 ends
    assert vu_ftoi(f2b(2.75), 0) == 2 and vu_ftoi(f2b(-2.75), 0) == M32 - 1
    assert vu_ftoi(f2b(1.5), 4) == 24               # 1.5 * 2^4
    assert vu_ftoi(f2b(1e10), 0) == 0x7fffffff
    assert vu_ftoi(f2b(-1e10), 0) == 0x80000000
    assert vu_itof(24, 4) == f2b(1.5) and vu_itof(M32, 0) == f2b(-1.0)
    # MIN/MAX order bit patterns, so -1.0 beats -2.0 without any arithmetic
    assert vu_max(f2b(-1.0), f2b(-2.0)) == f2b(-1.0)
    assert vu_min(f2b(-1.0), f2b(-2.0)) == f2b(-2.0)
    assert vu_max(f2b(3.0), f2b(-9.0)) == f2b(3.0)

    e = Emu(Fake(b''))

    def vset(n, *xs):
        e.vf[n] = [f2b(x) for x in xs]

    def vget(n):
        return tuple(b2f(b) for b in e.vf[n])

    # The transform every renderer in this ROM runs: rows in vf4..vf7, the
    # point in vf8, ACC chained across three MULA/MADDA, result in vf9.
    vset(4, 1, 0, 0, 0); vset(5, 0, 1, 0, 0)
    vset(6, 0, 0, 1, 0); vset(7, 10, 20, 30, 1)
    vset(8, 2, 3, 4, 1)
    for mn, ops in (('vmulax.xyzw', 'ACC, $vf4, $vf8'),
                    ('vmadday.xyzw', 'ACC, $vf5, $vf8'),
                    ('vmaddaz.xyzw', 'ACC, $vf6, $vf8'),
                    ('vmaddw.xyzw', '$vf9, $vf7, $vf8')):
        e.step(mn, ops)
    assert vget(9) == (12.0, 23.0, 34.0, 1.0), vget(9)
    # A partial write mask leaves the other components exactly as they were
    vset(10, 5, 5, 5, 5)
    e.step('vsub.xz', '$vf10, $vf10, $vf8')
    assert vget(10) == (3.0, 5.0, 1.0, 5.0), vget(10)
    # VF00 reads as (0,0,0,1) and never takes a write
    assert vget(0) == (0.0, 0.0, 0.0, 1.0)
    e.step('vadd.xyzw', '$vf0, $vf8, $vf8')
    assert vget(0) == (0.0, 0.0, 0.0, 1.0)
    # MR32 rotates the register one component left, wrapping x into w
    vset(11, 1, 2, 3, 4)
    e.step('vmr32.xyzw', '$vf12, $vf11')
    assert vget(12) == (2.0, 3.0, 4.0, 1.0), vget(12)
    e.step('vmr32.xyzw', '$vf11, $vf11')        # in place: x must not feed w
    assert vget(11) == (2.0, 3.0, 4.0, 1.0), vget(11)
    # DIV: a zero divisor saturates and raises D; 0/0 raises I instead
    vset(13, 1, 0, 0, -1)
    e.step('vdiv', '$vf13.x, $vf13.y')
    assert (e.vq, e.vi[16] & 0x30) == (0x7f7fffff, 0x20)
    e.step('vdiv', '$vf13.w, $vf13.y')
    assert (e.vq, e.vi[16] & 0x30) == (0xff7fffff, 0x20)
    e.step('vdiv', '$vf13.y, $vf13.z')
    assert (e.vq, e.vi[16] & 0x30) == (0x7f7fffff, 0x10)
    vset(14, 8, 2, -4, 0)
    e.step('vdiv', '$vf14.x, $vf14.y')
    assert (b2f(e.vq), e.vi[16] & 0x30) == (4.0, 0)
    e.step('vsqrt', '$vf14.z')                       # sqrt of a negative
    assert (b2f(e.vq), e.vi[16] & 0x30) == (2.0, 0x10)
    e.step('vmulq.xyzw', '$vf15, $vf14, $vf0')       # Q broadcast into a FMAC
    assert vget(15) == (16.0, 4.0, -8.0, 0.0), vget(15)
    # CLIP pushes six answers -- x,y,z each against +|w| and -|w| -- into a
    # 24-bit shift register. Here only "x above +w" and "y below -w" hold.
    vset(16, 2, -2, 0.5, 0); vset(17, 0, 0, 0, 1)
    e.vi[18] = 0
    e.step('vclipw', '$vf16, $vf17')
    assert e.vi[18] == 0x09, hex(e.vi[18])
    e.step('vclipw', '$vf16, $vf17')                 # shifts, never replaces
    assert e.vi[18] == 0x249, hex(e.vi[18])
    # LQC2/SQC2 move a whole quadword; QMTC2/QMFC2 move it through a GPR
    e.set('$a0', 0x00c00000)
    e.step('sqc2', '$vf9, 16($a0)')
    e.step('lqc2', '$vf18, 16($a0)')
    assert vget(18) == (12.0, 23.0, 34.0, 1.0)
    e.step('qmfc2', '$v0, $vf18')
    assert e.q('$v0') == sum(e.vf[18][i] << (32 * i) for i in range(4))
    e.step('qmtc2', '$v0, $vf19')
    assert e.vf[19] == e.vf[18]
    # The MAC flags feed VI16, which CFC2 reads. Subtracting a register from
    # itself makes all four components zero, so all four Z bits light up and
    # the status word reports zero without sign, underflow or overflow.
    vset(20, 1, 1, 1, 1)
    e.step('vsub.xyzw', '$vf21, $vf20, $vf20')       # every result is zero
    e.step('cfc2', '$v1, $vi17')
    assert e.get('$v1') == 0x000f, hex(e.get('$v1'))
    e.step('cfc2', '$v1, $vi16')
    assert e.get('$v1') & 0xf == 1
    e.step('cfc2', '$v1, $vi29')                     # VPU_STAT: VU0 idle
    assert e.get('$v1') == 0

    assert f2b(_rtz(1.0)) == 0x3f800000
    assert b2f(0x00000001) == 0.0 and b2f(0x7f800000) == FLT_MAX   # DAZ / clamp
    assert f2b(1e-45) == 0                                          # FTZ
    assert s64(0xffffffff00000001) < 0 and s32(0x00000001) > 0
    assert COND['bltz'](0xffffffff00000001, 0) is True
    assert decode_mmi(struct.pack('<I', 0x0085001a)) == ('div', '$a0, $a1')
    assert decode_mmi(struct.pack('<I', 0x0085001b)) == ('divu', '$a0, $a1')
    assert sx32(0xffffffff) == 0xffffffffffffffff
    assert sx32(0x7fffffff) == 0x7fffffff
    print('ok')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        demo()
    else:
        print(call(sys.argv[1], sys.argv[2], *[int(x, 0) for x in sys.argv[3:]]))
