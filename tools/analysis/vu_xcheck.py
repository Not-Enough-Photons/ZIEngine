"""Cross-check emu.py's VU0 against lift.py's VU0 over random state.

emu.py and lift.py are two independent models of the same hardware, and
difftest.py only compares them on whatever VU code a ROM function happens to
contain. This drives random instruction sequences over random register state
through both and compares every VF, the accumulator, Q and the flag words --
which is what catches a one-ulp disagreement in an opcode no function in the
ROM exercises hard.

usage: python vu_xcheck.py [seed]
"""
import os, random, struct, subprocess, sys, tempfile
import emu, lift

OPS = []
for d in ('xyzw', 'xyz', 'x', 'yw', 'zw', 'xzw'):
    for b in ('add', 'sub', 'mul', 'madd', 'msub'):
        for sfx in ('', 'x', 'y', 'z', 'w', 'q'):
            OPS.append((f'v{b}{sfx}.{d}', '$vf%d, $vf%d, $vf%d'))
            OPS.append((f'v{b}a{sfx}.{d}', 'ACC, $vf%d, $vf%d', 1))
    for b in ('max', 'mini'):
        for sfx in ('', 'x', 'w'):
            OPS.append((f'v{b}{sfx}.{d}', '$vf%d, $vf%d, $vf%d'))
    for b in ('move', 'mr32', 'ftoi0', 'ftoi4', 'ftoi12', 'ftoi15',
              'itof0', 'itof4', 'itof12', 'itof15'):
        OPS.append((f'v{b}.{d}', '$vf%d, $vf%d', 2))
OPS.append(('vopmula', 'ACC, $vf%d, $vf%d', 1))
OPS.append(('vopmsub', '$vf%d, $vf%d, $vf%d'))
OPS.append(('vclipw', '$vf%d, $vf%d', 2))
OPS.append(('vnop', ''))


def gen(rng, n):
    out = []
    for _ in range(n):
        e = rng.choice(OPS)
        mn, fmt = e[0], e[1]
        kind = e[2] if len(e) > 2 else 0
        regs = [rng.randrange(1, 8) for _ in range(3)]
        if mn in ('vdiv', 'vsqrt'):
            continue
        if kind == 1:
            out.append((mn, fmt % (regs[1], regs[2])))
        elif kind == 2:
            out.append((mn, fmt % (regs[0], regs[1])))
        elif fmt:
            out.append((mn, fmt % tuple(regs)))
        else:
            out.append((mn, ''))
        if rng.random() < 0.15:
            c = 'xyzw'[rng.randrange(4)]
            out.append(('vdiv', f'$vf{regs[1]}.{c}, $vf{regs[2]}.{c}'))
        if rng.random() < 0.08:
            out.append(('vsqrt', f'$vf{regs[2]}.{"xyzw"[rng.randrange(4)]}'))
    return out


def randbits(rng):
    r = rng.random()
    if r < 0.6:
        return emu.f2b(rng.uniform(-1000.0, 1000.0))
    if r < 0.7:
        return emu.f2b(rng.uniform(-1e-6, 1e-6))
    if r < 0.8:
        return emu.f2b(rng.choice([0.0, -0.0, 1e30, -1e30, 1e-42]))
    return rng.randrange(1 << 32)


def main():
    rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 7)
    bad = 0
    for trial in range(40):
        seq = gen(rng, 30)
        init = [[randbits(rng) for _ in range(4)] for _ in range(8)]
        e = emu.Emu.__new__(emu.Emu)
        e.vu_reset()
        e.r = {}
        for n in range(1, 8):
            e.vf[n] = list(init[n])
        for mn, ops in seq:
            e.vstep(mn, [x.strip() for x in ops.split(',')] if ops else [])
        want = [e.vf[n][i] for n in range(8) for i in range(4)]
        want += e.vacc + [e.vq, e.vmac, e.vi[16], e.vi[18]]

        body = '\n'.join('    ' + lift.lift_one(mn, ops, 0, set())
                         for mn, ops in seq)
        setup = '\n'.join(f'    vf[{n}][{i}] = {init[n][i]}u;'
                          for n in range(1, 8) for i in range(4))
        from difftest import OBJ_ADDR
        from emu import STACK_TOP
        import lift as _L
        pre = _L.PROLOGUE % ('vu cross-check', os.path.abspath('disc/SCUS_972.05').replace(chr(92),'/'),
                             0, 0, 0, OBJ_ADDR, OBJ_ADDR, OBJ_ADDR,
                             STACK_TOP, STACK_TOP, STACK_TOP)
        src = pre + f'''
int main() {{
{setup}
{body}
    for (int n = 0; n < 8; n++) for (int i = 0; i < 4; i++)
        printf("%u\\n", vf[n][i]);
    for (int i = 0; i < 4; i++) printf("%u\\n", vacc[i]);
    printf("%u\\n%u\\n%u\\n%u\\n", vq, vmac, vi[16], vi[18]);
    return 0;
}}
'''
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, 'a.cpp')
            x = os.path.join(d, 'a.exe')
            open(f, 'w', encoding='utf-8').write('#include <cstdio>\n' + src)
            r = subprocess.run(lift_cxx() + [f, '-o', x], capture_output=True,
                               text=True)
            if r.returncode:
                print(r.stderr[-3000:])
                return 1
            got = [int(v) for v in subprocess.run([x], capture_output=True,
                                                  text=True).stdout.split()]
        if got != want:
            bad += 1
            print(f'trial {trial}: MISMATCH')
            for k, (g, w) in enumerate(zip(got, want)):
                if g != w:
                    print(f'  slot {k}: got {g:#010x} want {w:#010x}')
            for mn, ops in seq:
                print('   ', mn, ops)
            if bad > 1:
                return 1
    print('mismatched trials:', bad)
    return 1 if bad else 0


def lift_cxx():
    from difftest import CXX
    return CXX


if __name__ == '__main__':
    sys.exit(main())
