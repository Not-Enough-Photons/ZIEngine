"""Measure what a large lifted file actually costs to compile.

LIFT_MAX_KB exists because clang's memory use on huge generated functions is
superlinear -- that cap was set back when difftest compiled at -O2 and the
lifted code had no step limit, which is what took the machine down. Both are
fixed, so the cap is worth re-measuring rather than inheriting.
"""
import os, subprocess, sys, threading, time
import psutil

CXX = [sys.executable, '-m', 'ziglang', 'c++', '-O0', '-ffp-contract=off',
       '-fno-strict-aliasing', '-std=c++17']


def peak_rss(cmd, timeout=600):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    top = 0
    def sample():
        nonlocal top
        try:
            pr = psutil.Process(p.pid)
            while p.poll() is None:
                try:
                    m = pr.memory_info().rss
                    for c in pr.children(recursive=True):
                        try: m += c.memory_info().rss
                        except Exception: pass
                    top = max(top, m)
                except Exception:
                    pass
                time.sleep(0.05)
        except Exception:
            pass
    t = threading.Thread(target=sample, daemon=True); t.start()
    t0 = time.time()
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); return None, None, timeout, b'TIMEOUT'
    return p.returncode, top, time.time() - t0, err


if __name__ == '__main__':
    import difftest
    for path in sys.argv[1:]:
        src = open(path, encoding='utf-8').read()
        drv = 'scratch/_mp.cpp'
        d = (difftest.DRIVER_OBJ.replace('%d', '512')
             .replace('%s', '\x00S\x00').replace('%%', '%')
             .replace('\x00S\x00', src))
        open(drv, 'w', encoding='utf-8').write(d)
        rc, rss, secs, err = peak_rss(CXX + [drv, '-o', 'scratch/_mp.exe'])
        kb = len(src) // 1024
        print(f'{kb:6d} KB src  rc={rc}  peak {rss/1e6 if rss else 0:8.0f} MB '
              f'  {secs:6.1f}s   {os.path.basename(path)}')
        if rc:
            print('   ', err.decode(errors='replace')[:200])
