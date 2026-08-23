"""Lift and verify every function in the worklist, with no API and no human.

lift.py turns R5900 machine code into compilable C++; difftest.py decides
whether that C++ actually behaves like the ROM. Chaining them gives a
decompiler whose output is *verified* rather than merely plausible, and it
runs entirely locally.

The result is not idiomatic C++ -- it is register-machine code with gotos, the
same first pass Ghidra or Hex-Rays emit. Its value is being provably correct,
so a human rewrite has a reference that is known to match instead of a guess.

usage:
    python bulk_lift.py [--limit N] [--workers N] [--elf PATH]
    python bulk_lift.py report
"""
import argparse, concurrent.futures as cf, json, os, re, subprocess, sys, threading

def save(led, path):
    """Write via a temp file and rename. A plain json.dump leaves a truncated,
    unparseable ledger if the batch is killed mid-write -- which happened."""
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump(led, fh, indent=1)
    os.replace(tmp, path)

LEDGER = 'decomp/lift_ledger.json'
OUTDIR = 'decomp/lifted'
WORKLIST = 'decomp/worklist.json'
_lock = threading.Lock()


def one(elf, w):
    name = w['name']
    # Include the address in the filename and key the ledger by it. 66 names
    # in this ROM belong to more than one function -- C++ overloads, plus
    # statics with the same name in different translation units -- so a
    # name-keyed ledger silently overwrote 74 results, and a name-keyed
    # filename let one function's lift overwrite another's verified output.
    slug = re.sub(r'[^A-Za-z0-9_]', '_', name) + f'__{w["addr"]:08x}'
    path = f'{OUTDIR}/{slug}.cpp'
    objn = w['objsize'] or 4
    try:
        r = subprocess.run([sys.executable, 'lift.py', elf, hex(w['addr']),
                            str(objn)], capture_output=True, text=True,
                           timeout=120)
    except subprocess.TimeoutExpired:
        return {'name': name, 'addr': w['addr'], 'status': 'unliftable',
                'detail': 'lift timeout'}
    if r.returncode != 0:
        why = (r.stderr.strip().splitlines() or ['?'])[-1]
        return {'name': name, 'addr': w['addr'], 'status': 'unliftable',
                'detail': why[:120]}
    # Re-measured after the switch to -O0 and the addition of the step
    # budget: 2.5 MB of generated C++ compiles in 21s at 1.2 GB peak, and the
    # cost is linear, not superlinear as it was at -O2. The old 48 KB cap was
    # rejecting 386 functions that compile fine, so it now only guards
    # against a genuine runaway.
    MAXKB = int(os.environ.get('LIFT_MAX_KB', 4096))
    if len(r.stdout) > MAXKB * 1024:
        return {'name': name, 'addr': w['addr'], 'status': 'too_large',
                'detail': f'{len(r.stdout)//1024} KB of generated C++ (cap {MAXKB})'}
    open(path, 'w', encoding='utf-8').write(r.stdout)

    try:
        v = subprocess.run([sys.executable, 'difftest.py', elf, hex(w['addr']),
                            path, f'--obj={objn}'], capture_output=True,
                           text=True, timeout=420)
    except subprocess.TimeoutExpired:
        return {'name': name, 'addr': w['addr'], 'status': 'mismatch',
                'detail': 'verify timeout'}
    if v.returncode == 0:
        return {'name': name, 'addr': w['addr'], 'status': 'verified',
                'file': path, 'size': w['size'],
                'detail': (v.stdout.strip().splitlines() or [''])[-1].strip()}
    tail = (v.stdout or v.stderr).strip().splitlines()
    return {'name': name, 'addr': w['addr'], 'status': 'mismatch',
            'file': path, 'size': w['size'],
            'detail': (tail[-1] if tail else '')[:120]}


def report():
    if not os.path.exists(LEDGER):
        raise SystemExit('no ledger yet')
    led = json.load(open(LEDGER))
    import collections
    c = collections.Counter(v['status'] for v in led.values())
    ok = [v for v in led.values() if v['status'] == 'verified']
    print(f'\nattempted {len(led)}')
    for k, n in c.most_common():
        print(f'   {k:12s} {n:5d}  {100 * n / len(led):5.1f}%')
    print(f'\nVERIFIED AGAINST THE ROM: {len(ok)} functions, '
          f'{sum(v.get("size", 0) for v in ok):,} bytes of machine code')
    why = collections.Counter(v['detail'].split('(')[0].strip()
                              for v in led.values()
                              if v['status'] == 'unliftable')
    if why:
        print('\ntop reasons a function could not be lifted:')
        for k, n in why.most_common(8):
            print(f'   {n:5d}  {k[:70]}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', nargs='?', default='run')
    ap.add_argument('--elf', default='disc/SCUS_972.05')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--workers', type=int,
                default=int(os.environ.get('LIFT_WORKERS', 4)))
    a = ap.parse_args()
    if a.cmd == 'report':
        return report()

    work = json.load(open(WORKLIST))
    led = json.load(open(LEDGER)) if os.path.exists(LEDGER) else {}
    todo = [w for w in work if f"{w['addr']:08x}" not in led]
    if a.limit:
        todo = todo[:a.limit]
    os.makedirs(OUTDIR, exist_ok=True)
    print(f'{len(todo)} to lift ({len(led)} already done), workers={a.workers}')

    done = ok = 0
    with cf.ThreadPoolExecutor(a.workers) as pool:
        futs = [pool.submit(one, a.elf, w) for w in todo]
        for fut in cf.as_completed(futs):
            res = fut.result()
            with _lock:
                led[f"{res['addr']:08x}"] = res
                done += 1
                ok += res['status'] == 'verified'
                if done % 25 == 0 or res['status'] == 'verified':
                    save(led, LEDGER)
                if done % 20 == 0:
                    print(f'  {done}/{len(todo)}  verified so far: {ok}')
    save(led, LEDGER)
    report()


if __name__ == '__main__':
    main()
