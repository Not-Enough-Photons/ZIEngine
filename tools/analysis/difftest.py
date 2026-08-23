"""Differentially test a decompiled function against the ROM that defines it.

Runs the original R5900 code in emu.py and the rewritten C++ compiled natively
by zig, over the same inputs, and compares every result. This is behavioural
equivalence, not a byte match -- byte matching needs Metrowerks MIPS 2.4.1.
For a pure function it is the stronger claim anyway: it checks what the code
does, not which instructions a compiler happened to pick.

Floats are compared as raw bit patterns, so a one-ulp disagreement fails.

usage: python difftest.py <SCUS_972.05> <Function> <decomp.cpp> [entry] [--float]
"""
import os, random, struct, subprocess, sys, tempfile
from disasm import Image
from emu import Emu, Machine, Unsupported, b2f, f2b

DRIVER_U32 = '''
#include <cstdio>
#include <cstdlib>
%s
int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++)
        printf("%%u\\n", (unsigned)%s((unsigned)strtoul(argv[i], 0, 10)));
    return 0;
}
'''

DRIVER_F32 = '''
#include <cstdio>
#include <cstdlib>
#include <cstring>
%s
int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        unsigned b = (unsigned)strtoul(argv[i], 0, 16);
        float in; memcpy(&in, &b, 4);
        float r = %s(in);
        unsigned o; memcpy(&o, &r, 4);
        printf("%%u\\n", o);
    }
    return 0;
}
'''


# Object mode: the decomp file supplies
#     extern "C" unsigned test_entry(unsigned char* obj, unsigned arg);
# so the harness never needs to know the class layout. Random bytes go in,
# the return value and the whole mutated object come back out -- which also
# catches setters, not just return values.
DRIVER_OBJ = '''
#include <cstdio>
#include <cstdlib>
#include <cstring>
%s
alignas(16) static unsigned char obj[%d];
int main(int argc, char** argv) {
    for (int i = 1; i + 1 < argc; i += 2) {
        const char* h = argv[i];
        for (int b = 0; b < %d; b++) {
            char t[3] = { h[2*b], h[2*b+1], 0 };
            obj[b] = (unsigned char)strtoul(t, 0, 16);
        }
        unsigned r = test_entry(obj, (unsigned)strtoul(argv[i+1], 0, 10));
        printf("%%08x", r);
        for (int b = 0; b < %d; b++) printf("%%02x", obj[b]);
        printf("\\n");
    }
    return 0;
}
'''

OBJ_ADDR = 0x00c00000          # clear of both the image and the stack

# -O0 on purpose. This harness checks behaviour, not speed, so optimisation
# buys nothing -- and lifted code is pathological for an optimiser: single
# functions of thousands of lines with hundreds of goto labels make clang's
# memory use superlinear. -O0 compiles them in a fraction of the memory and
# time, and keeps float arithmetic strictly IEEE (no FMA contraction).
CXX = [sys.executable, '-m', 'ziglang', 'c++', '-O0',
       '-ffp-contract=off', '-fno-strict-aliasing', '-std=c++17']


def obj_words(rng, nbytes, vtable=None):
    """Fill an object word-wise with values that are sane read either way.

    Uniform random bytes make any float field a NaN or a huge exponent, and
    the R5900 FPU has neither NaN nor Inf -- so those cases would report
    divergence that says nothing about the decompilation.
    """
    out = b''
    for _ in range((nbytes + 3) // 4):
        if rng.random() < 0.5:
            out += struct.pack('<f', rng.uniform(-1000.0, 1000.0))
        else:
            out += struct.pack('<I', rng.choice(
                [0, 1, 2, 3, 255, rng.randrange(256), rng.randrange(1 << 16)]))
    out = out[:nbytes]
    if vtable is not None and nbytes >= 4:
        # A real vtable pointer at offset 0. Without it every virtual call in
        # the object jumps to garbage and the function cannot run at all.
        out = struct.pack('<I', vtable) + out[4:]
    return out


def ARGS(arg):
    """The four integer argument registers, identical on both sides.

    lift.py's test_entry must agree with this exactly. Distinct values catch
    a lift that swaps two arguments; small values keep a third argument from
    reading as a huge loop count and losing the function to the step limit.
    """
    return [OBJ_ADDR, arg, (arg + 3) & 0x7f, (arg + 7) & 0x7f]


def obj_mode(elf, func, cpp, entry, nbytes, cases=0, retf=False):
    img = Image(elf)
    _s, addr, size = img.func(func)
    if not cases:
        # Every case is a full interpreted run plus a whole-object compare, so
        # a fixed 400 makes a 2KB function over a 1.5KB object take minutes.
        # Scale with the work; small functions keep full coverage.
        cost = max(size * max(nbytes, 64), 40000)
        cases = max(50, min(400, 400 * 40000 // cost))
    rng = random.Random(20020513)
    from disasm import vtables
    vt = vtables(img)
    states = []
    for i in range(cases):
        # vtable chosen by case index, not off the rng stream, so lift.py's
        # profiling pass can reproduce the exact same object states
        states.append((obj_words(rng, nbytes, vt[i % len(vt)] if vt else None),
                       rng.choice([0, 1, 2, 3, 4, 5, 7, 255, 1000])))
    expect = []
    try:
        for blob, arg in states:
            e = Emu(img, Machine(img))
            for i, b in enumerate(blob):
                e.m.wb(OBJ_ADDR + i, b)
            rv = e.run(addr, size, ARGS(arg), [float(arg)], limit=200000)
            if retf:
                rv = f2b(e.retf())
            after = bytes(e.m.load(OBJ_ADDR + i, 1) for i in range(nbytes))
            expect.append(f'{rv:08x}' + after.hex())
    except Unsupported as ex:
        raise SystemExit(f'interpreter cannot run this function: {ex}')

    with tempfile.TemporaryDirectory() as d:
        src = open(cpp, encoding='utf-8').read()
        drv = os.path.join(d, 'drv.cpp'); exe = os.path.join(d, 'drv.exe')
        # Substitute, don't %-format: decompiled C++ contains modulo operators
        # and any bare % in the source blows up printf-style interpolation.
        drv_src = (DRIVER_OBJ.replace('%d', str(nbytes))
                   .replace('%s', '\x00SRC\x00').replace('%%', '%')
                   .replace('\x00SRC\x00', src))
        open(drv, 'w').write(drv_src)
        r = subprocess.run(CXX + [drv, '-o', exe], capture_output=True,
                           text=True, timeout=180)
        if r.returncode:
            print(r.stderr[:2000]); raise SystemExit('compile failed')
        argv = []
        for blob, arg in states:
            argv += [blob.hex(), str(arg)]
        got, rcs = [], []
        i = 0
        while i < len(argv):                  # batch by length: a big object
            chunk, n = [], 0                  # blows the 32k command line
            while i < len(argv) and n < 24000:
                chunk.append(argv[i]); n += len(argv[i]) + 1; i += 1
            if len(chunk) % 2:                # keep (object, arg) pairs together
                i -= 1; chunk.pop()
            # a lifted runaway exits(97) on its budget, but a genuine hang
            # would otherwise sit there holding pages forever
            try:
                out = subprocess.run([exe] + chunk, capture_output=True,
                                     text=True, timeout=120)
            except subprocess.TimeoutExpired:
                print('  driver timed out'); return 1
            got += out.stdout.split()
            if out.returncode:
                rcs.append(out.returncode)

    # A short result list means the driver died partway: a trap on an
    # unmodelled indirect jump, a budget bail, or a crash. zip() would
    # silently compare only the surviving prefix and call that a pass, so
    # the count is checked before the values.
    print(f'{func}: {len(states)} random object states tested against the ROM')
    if len(got) != len(expect):
        why = {97: 'budget/trap exit(97)'}.get(rcs[0] if rcs else 0,
                                               f'exit {rcs[0] if rcs else 0}')
        print(f'  driver produced {len(got)} of {len(expect)} results '
              f'-- {why}')
        return 1
    bad = [(i, e, g) for i, (e, g) in enumerate(zip(expect, got)) if e != g]
    for i, e, g in bad[:5]:
        print(f'  MISMATCH case {i}\n    ROM {e}\n    C++ {g}')
    if bad:
        print(f'  {len(bad)} mismatches'); return 1
    print(f'  all {len(states)} match (return value + full object image)')
    return 0


def build(cpp, entry, workdir, driver):
    src = open(cpp, encoding='utf-8').read()
    drv = os.path.join(workdir, 'drv.cpp')
    exe = os.path.join(workdir, 'drv.exe')
    # same reason as obj mode: never %-format around decompiled source
    open(drv, 'w').write(driver.replace('%%', '\x01').replace('%s', '\x00', 1)
                         .replace('%s', entry).replace('\x00', src)
                         .replace('\x01', '%'))
    r = subprocess.run(CXX + [drv, '-o', exe], capture_output=True,
                       text=True, timeout=180)
    if r.returncode:
        print(r.stderr[:2000])
        raise SystemExit('compile failed')
    return exe


def int_inputs():
    """Boundaries around every power of two, plus a random 32-bit sample."""
    vals = set(range(0, 1200))
    for b in range(32):
        for d in (-2, -1, 0, 1, 2):
            v = (1 << b) + d
            if 0 <= v <= 0xffffffff:
                vals.add(v)
    rng = random.Random(20020513)                 # the ROM's build date
    vals.update(rng.randrange(0, 1 << 32) for _ in range(3000))
    return sorted(vals)


def float_inputs():
    rng = random.Random(20020513)
    vals = {0.0, -0.0, 0.5, -0.5, 1.0, -1.0, 2.0, -2.0}
    vals.update(i / 64.0 for i in range(-512, 513))       # dense near the knee
    vals.update(rng.uniform(-1e4, 1e4) for _ in range(1500))
    vals.update(rng.uniform(-1.0, 1.0) for _ in range(1500))
    return sorted(vals)


def main(elf, func, cpp, entry=None, *flags):
    allf = list(flags) + ([entry] if entry and entry.startswith('--') else [])
    if entry and entry.startswith('--'):
        entry = None
    for f in allf:                              # --obj=<sizeof(class)>
        if f.startswith('--obj='):
            return obj_mode(elf, func, cpp, entry, int(f.split('=')[1], 0),
                            retf='--retf' in allf)
    isf = '--float' in allf
    entry = entry or func.split('::')[-1]
    img = Image(elf)
    _s, addr, size = img.func(func)

    vals = float_inputs() if isf else int_inputs()
    expect = []
    try:
        for v in vals:
            e = Emu(img, Machine(img))
            if isf:
                e.run(addr, size, [], [v], limit=200000)
                expect.append(f2b(e.retf()))
            else:
                expect.append(e.run(addr, size, [v], limit=200000))
    except Unsupported as ex:
        raise SystemExit(f'interpreter cannot run this function: {ex}')

    with tempfile.TemporaryDirectory() as d:
        exe = build(cpp, entry, d, DRIVER_F32 if isf else DRIVER_U32)
        argv = [f'{f2b(v):08x}' for v in vals] if isf else [str(v) for v in vals]
        got = []
        for i in range(0, len(argv), 400):        # stay under the argv limit
            out = subprocess.run([exe] + argv[i:i + 400],
                                 capture_output=True, text=True)
            got += [int(x) for x in out.stdout.split()]

    bad = [(v, e, g) for v, e, g in zip(vals, expect, got) if e != g]
    kind = 'float' if isf else 'u32'
    print(f'{func}: {len(vals)} {kind} inputs tested against the ROM')
    for v, e, g in bad[:10]:
        if isf:
            print(f'  MISMATCH  in={v!r}  ROM={b2f(e)!r}  C++={b2f(g)!r}')
        else:
            print(f'  MISMATCH  in={v}  ROM={e}  C++={g}')
    if bad:
        print(f'  {len(bad)} mismatches')
        return 1
    print(f'  all {len(vals)} match (bit-exact)' if isf else
          f'  all {len(vals)} match')
    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
