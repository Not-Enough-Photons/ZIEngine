import glob, sys, collections
from zrdr import load
files = sorted(glob.glob(sys.argv[1] + '/**/*.rdr', recursive=True))
ok = fail = 0; errs = collections.Counter(); nodes = 0
def count(t): return 1 + sum(count(c) for c in t if isinstance(c, list))
for p in files:
    try:
        t = load(p); ok += 1; nodes += count(t)
    except Exception as e:
        fail += 1; errs[f'{type(e).__name__}: {e}'] += 1
        if fail <= 8: print('FAIL', p, e)
print(f'\nparsed {ok}/{len(files)} ({100*ok/len(files):.1f}%)  arrays built: {nodes:,}')
for e, n in errs.most_common(10): print(f'  {n:4d}  {e}')
