"""Re-run difftest over already-lifted C++ with no re-lifting.

difftest used to compare `zip(expect, got)`, so a driver that died partway
through its batch had its surviving prefix compared and reported as a pass.
Files containing dispatch() could hit `default: std::_Exit(97)` on an
unprofiled indirect target and do exactly that. This re-checks them under the
fixed harness and says which "verified" results do not survive.

usage: python reverify.py <names.json> [--workers N]
"""
import concurrent.futures as cf, json, subprocess, sys, os

ELF = 'disc/SCUS_972.05'
wl = {w['name']: w for w in json.load(open('decomp/worklist.json'))}
led = json.load(open('decomp/lift_ledger.json'))


def one(name):
    w, e = wl.get(name), led[name]
    if not w:
        return name, 'no-worklist', ''
    try:
        v = subprocess.run([sys.executable, 'difftest.py', ELF, hex(w['addr']),
                            e['file'], f"--obj={w['objsize'] or 4}"],
                           capture_output=True, text=True, timeout=420)
    except subprocess.TimeoutExpired:
        return name, 'timeout', ''
    tail = (v.stdout or v.stderr).strip().splitlines()
    return name, ('ok' if v.returncode == 0 else 'REGRESSED'), \
        (tail[-1] if tail else '')[:100]


if __name__ == '__main__':
    names = json.load(open(sys.argv[1]))
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    bad, n = [], 0
    with cf.ThreadPoolExecutor(workers) as p:
        for name, st, detail in p.map(one, names):
            n += 1
            if st != 'ok':
                bad.append({'name': name, 'status': st, 'detail': detail})
                print(f'  [{n}/{len(names)}] {st:10s} {name[:50]:50s} {detail}')
            elif n % 50 == 0:
                print(f'  [{n}/{len(names)}] ok so far, {len(bad)} regressed')
    json.dump(bad, open('scratch/regressed.json', 'w'), indent=1)
    print(f'\n{len(names)} re-checked, {len(bad)} no longer verify')
