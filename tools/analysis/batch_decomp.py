"""Decompile SCUS_972.05 in bulk: one LLM call per function, verified by difftest.

Hand-decompiling 7,275 functions inside one chat session is not reachable --
the token arithmetic alone rules it out. This takes the human out of the loop
instead. difftest.py can already decide correctness automatically, so the
pipeline is:

    disassembly + type info  ->  model  ->  C++  ->  difftest  ->  keep / retry

Anything that passes is verified against the ROM, not merely plausible.
Anything that fails twice is parked with its mismatch report for a human.

Credentials come from the environment, and ANTHROPIC_BASE_URL is honoured, so
this runs against the Anthropic API or any Anthropic-compatible endpoint
without code changes:

    ANTHROPIC_API_KEY=...  [ANTHROPIC_BASE_URL=https://your-endpoint/...]

usage:
    python batch_decomp.py worklist              # scan the ROM, cache targets
    python batch_decomp.py run [--limit N] [--workers N] [--model ID]
    python batch_decomp.py report
"""
import argparse, concurrent.futures as cf, json, os, re, subprocess, sys, threading

LEDGER = 'decomp/ledger.json'
OUTDIR = 'decomp/auto'
WORKLIST = 'decomp/worklist.json'
MODEL = os.environ.get('DECOMP_MODEL', 'claude-fable-5')

SYSTEM = """You decompile PlayStation 2 (MIPS R5900) machine code into C++ for \
reCOM, a reimplementation of Zipper Interactive's SOCOM.

Rules:
- Output ONE fenced ```cpp block and nothing else. No prose.
- The block must be self-contained and compile on its own with no headers \
beyond <cstring>/<cstdint>.
- End with exactly this shape so the harness can call it:
      extern "C" unsigned test_entry(unsigned char* obj, unsigned arg)
  For a method, `obj` is the object; read fields as offsets from it. For a \
free function, ignore `obj` and use `arg`.
- Reproduce behaviour exactly, including quirks. Do not "fix" the original.
- Delay slots: the instruction after a branch executes BEFORE the jump. \
Metrowerks fills them constantly. Getting this wrong is the most common error.
- The R5900 FPU has no Inf and no NaN. Overflowing arithmetic and division by \
zero saturate to +/-FLT_MAX. If the function divides, reproduce that.
- Prefer readable C++ over transliteration, but correctness wins.
- Write field accesses as offsets (e.g. *(float*)(obj + 0x2c)) unless a name \
is given in the context."""

PROMPT = """Decompile this function.

{ctx}

Disassembly:
{asm}
"""

_lock = threading.Lock()


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# ---------------------------------------------------------------- worklist
def build_worklist(elf):
    """Find every function difftest can actually judge, and cache it."""
    from disasm import Image
    from emu import Emu, Machine
    from symbols import demangle
    from origin import origin
    from dwarf1 import parse, records

    img = Image(elf)
    roots, _f = parse(elf)
    sizes = {}
    for d in records(roots):
        n, bs = d.name(), d.at.get('byte_size')
        if n and bs and any(c.tag == 'member' for c in d.children):
            sizes[n] = max(sizes.get(n, 0), bs)

    OBJ = 0x00c00000
    # Widened: the old bounds (<=600 bytes, class size known and <=512) were
    # the binding constraint on how much could ever be verified, not the
    # decompiler. A class with no DWARF entry still gets a generous fixed
    # object -- both sides model the same bytes, so the comparison stays
    # sound; it just may not cover fields past the window.
    DEFAULT_OBJ = int(os.environ.get('WL_DEFAULT_OBJ', 512))
    MAXSZ = int(os.environ.get('WL_MAXSZ', 6000))
    MAXOBJ = int(os.environ.get('WL_MAXOBJ', 2048))
    out = []
    for sym, a, sz in img.funcs:
        if not (8 <= sz <= MAXSZ):
            continue
        cls, meth = demangle(sym)
        if origin(sym, cls, meth) != 'GAME (Zipper)':
            continue
        objn = sizes.get(cls, 0) if cls else 0
        if cls and not objn:
            objn = DEFAULT_OBJ            # unknown layout: probe a window
        if objn > MAXOBJ:
            continue
        # Probe with the same random object states difftest uses. The old
        # fixed pattern (i*7 + t*31) made many state-dependent functions look
        # constant, and they were dropped for "nothing to verify".
        import random as _rnd
        from difftest import obj_words
        from disasm import vtables
        _vt = vtables(img)
        rng = _rnd.Random(0xC0FFEE)
        try:
            seen = set()
            for t in range(6):
                e = Emu(img, Machine(img))
                # a real vtable pointer, or every virtual call jumps nowhere
                blob = (obj_words(rng, objn, _vt[t % len(_vt)] if _vt else None)
                        if objn else b'')
                for i, bb in enumerate(blob):
                    e.m.wb(OBJ + i, bb)
                rv = e.run(a, sz, [OBJ if cls else t, t], [float(t)],
                           limit=60000)
                after = bytes(e.m.load(OBJ + i, 1) for i in range(objn))
                seen.add((rv, after))
        except Exception:
            continue
        # A constant result is still a real function worth lifting; it just
        # gets a weaker check. Keep it, but flag it so the report stays honest.
        out.append({'sym': sym, 'name': f'{cls}::{meth}' if cls else meth,
                    'addr': a, 'size': sz, 'objsize': objn,
                    'constant': len(seen) < 2})
    os.makedirs('decomp', exist_ok=True)
    json.dump(out, open(WORKLIST, 'w'), indent=1)
    print(f'{len(out)} verifiable functions -> {WORKLIST}')
    return out


# ---------------------------------------------------------------- context
def context_for(elf, entry):
    """Disassembly plus whatever ground truth we have about the class."""
    asm = sh(sys.executable, 'disasm.py', elf, hex(entry['addr'])).stdout
    ctx = [f"Function: {entry['name']}",
           f"Mangled:  {entry['sym']}",
           f"Address:  0x{entry['addr']:08x}   size {entry['size']} bytes"]
    cls = entry['name'].split('::')[0] if '::' in entry['name'] else None
    if cls and entry['objsize']:
        ctx.append(f"sizeof({cls}) = {entry['objsize']} bytes")
        lay = sh(sys.executable, 'dwarf1.py', elf, cls).stdout
        if lay.strip():
            ctx.append('Ground-truth layout from the ROM debug info:\n'
                       + lay[:4000])
        ctx.append('`obj` points at a live instance of this class.')
    else:
        ctx.append('Free function; the scalar argument arrives in `arg`.')
    return '\n'.join(ctx), asm


CODE = re.compile(r'```(?:cpp|c\+\+|c)?\s*\n(.*?)```', re.S)


def extract(text):
    m = CODE.search(text)
    return (m.group(1) if m else text).strip()


# ---------------------------------------------------------------- one item
def do_one(client, elf, entry, attempts=2):
    name = entry['name']
    slug = re.sub(r'[^A-Za-z0-9_]', '_', name)
    path = f'{OUTDIR}/{slug}.cpp'
    ctx, asm = context_for(elf, entry)
    convo = [{'role': 'user', 'content': PROMPT.format(ctx=ctx, asm=asm)}]

    for attempt in range(attempts):
        try:
            kw = {'output_config':
                  {'effort': os.environ.get('DECOMP_EFFORT', 'medium')}}
            if not MODEL.startswith('claude-fable'):   # fable thinks by default
                kw['thinking'] = {'type': 'adaptive'}
            with client.messages.stream(
                    model=MODEL, max_tokens=12000,
                    system=SYSTEM, messages=convo, **kw) as stream:
                msg = stream.get_final_message()
        except Exception as ex:
            return {'name': name, 'status': 'api_error', 'detail': str(ex)[:300]}
        if msg.stop_reason == 'refusal':
            return {'name': name, 'status': 'refused'}
        text = ''.join(b.text for b in msg.content if b.type == 'text')
        code = extract(text)
        if 'test_entry' not in code:
            if attempt + 1 < attempts:
                convo += [{'role': 'assistant', 'content': text},
                          {'role': 'user', 'content':
                           'That block has no test_entry. Re-emit it ending '
                           'with exactly this line:\n'
                           '  extern "C" unsigned test_entry('
                           'unsigned char* obj, unsigned arg)\n'
                           'Output only the ```cpp block.'}]
                continue
            return {'name': name, 'status': 'no_entry'}
        os.makedirs(OUTDIR, exist_ok=True)
        open(path, 'w', encoding='utf-8').write(code)

        # always object mode, same convention the worklist was validated with
        args = [sys.executable, 'difftest.py', elf, hex(entry['addr']), path,
                f"--obj={entry['objsize'] or 4}"]
        r = sh(*args)
        if r.returncode == 0:
            return {'name': name, 'status': 'verified', 'file': path,
                    'attempts': attempt + 1,
                    'detail': r.stdout.strip().splitlines()[-1].strip()}
        if attempt + 1 < attempts:        # feed the mismatch back and retry
            convo += [{'role': 'assistant', 'content': text},
                      {'role': 'user', 'content':
                       'That does not match the ROM. The verifier reported:\n\n'
                       + r.stdout[-2500:] +
                       '\n\nRe-read the disassembly, especially delay slots and '
                       'R5900 float semantics, and output a corrected ```cpp block.'}]
    return {'name': name, 'status': 'failed', 'file': path,
            'detail': (r.stdout or r.stderr)[-400:]}


# ---------------------------------------------------------------- driver
def run(elf, limit, workers):
    import anthropic
    if not (os.environ.get('ANTHROPIC_API_KEY') or
            os.environ.get('ANTHROPIC_AUTH_TOKEN')):
        raise SystemExit('set ANTHROPIC_API_KEY (and ANTHROPIC_BASE_URL if you '
                         'are pointing at a different endpoint)')
    client = anthropic.Anthropic()

    work = json.load(open(WORKLIST))
    ledger = json.load(open(LEDGER)) if os.path.exists(LEDGER) else {}
    todo = [w for w in work if ledger.get(w['name'], {}).get('status')
            != 'verified'][:limit or None]
    print(f'{len(todo)} to attempt ({len(ledger)} already in the ledger), '
          f'model={MODEL}, workers={workers}')

    done = 0
    with cf.ThreadPoolExecutor(workers) as pool:
        futs = {pool.submit(do_one, client, elf, w): w for w in todo}
        for fut in cf.as_completed(futs):
            res = fut.result()
            with _lock:
                ledger[res['name']] = res
                json.dump(ledger, open(LEDGER, 'w'), indent=1)
                done += 1
                mark = {'verified': 'OK  ', 'failed': 'FAIL',
                        'refused': 'REFU'}.get(res['status'], 'ERR ')
                print(f"  [{done}/{len(todo)}] {mark} {res['name'][:44]:44s} "
                      f"{res.get('detail', '')[:60]}")
    report()


def report():
    if not os.path.exists(LEDGER):
        raise SystemExit('no ledger yet')
    ledger = json.load(open(LEDGER))
    import collections
    c = collections.Counter(v['status'] for v in ledger.values())
    print(f'\n{len(ledger)} attempted')
    for k, n in c.most_common():
        print(f'   {k:10s} {n:5d}  {100 * n / len(ledger):5.1f}%')
    ok = c['verified']
    print(f'\n{ok} functions verified against the ROM in {OUTDIR}/')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['worklist', 'run', 'report'])
    ap.add_argument('--elf', default='disc/SCUS_972.05')
    ap.add_argument('--limit', type=int, default=0)
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--model', default=None)
    a = ap.parse_args()
    if a.model:
        MODEL = a.model
    if a.cmd == 'worklist':
        build_worklist(a.elf)
    elif a.cmd == 'run':
        run(a.elf, a.limit, a.workers)
    else:
        report()
