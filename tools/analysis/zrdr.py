"""zReader (.rdr) parser -- GameZ / SOCOM.

Grammar transcribed from reCOM src/gamez/zReader/zrdr_parse.cpp:
  ReadToken  -- ';' line comments, '#' preproc lines, '(' ')' delims,
                '"' quoted -> forced string, else whitespace-delimited atom
  ReadArray  -- nested lists; element[0] of each array is its length
  MakeUnion  -- strtol full-match -> int, strtod full-match -> float, else str
"""
import re, sys

INT_RE = re.compile(r'^[+-]?[0-9]+$')
# _get_pptoken() recognises exactly these; any other '#' is an ordinary atom
# character (the on-screen keyboard data uses a bare '#' as a key label).
PREPROC_RE = re.compile(r'#(ifdef|else|endif|include)\b')

def _atom(text, quoted):
    if quoted or not text:
        return text
    if INT_RE.match(text):
        return int(text)
    try:
        # ponytail: Python float() != C strtod on hex floats ("0x1p3").
        # Absent from all 461 shipped files; add a hex-float branch if one shows up.
        if '_' not in text:
            return float(text)
    except ValueError:
        pass
    return text

def tokenize(src):
    """Yield ('(' | ')' | ('atom', value))."""
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == ';':                                  # comment to EOL
            i = src.find('\n', i)
            if i < 0: return
            continue
        if c == '#' and PREPROC_RE.match(src, i):     # directive to EOL
            j = src.find('\n', i)
            yield ('preproc', src[i:j if j > 0 else n])
            if j < 0: return
            i = j
            continue
        if c in '()':
            yield c; i += 1; continue
        if c.isspace():
            i += 1; continue
        if c == '"':                                  # quoted -> always string
            j = src.find('"', i + 1)
            if j < 0:                                 # unterminated: take rest
                yield ('atom', _atom(src[i+1:], True)); return
            yield ('atom', _atom(src[i+1:j], True)); i = j + 1; continue
        j = i                                         # bare atom
        while j < n and not src[j].isspace() and src[j] not in '();"':
            j += 1
        yield ('atom', _atom(src[i:j], False)); i = j

def parse(src, keep_preproc=False):
    """Parse reader source into nested lists. Returns the top-level list."""
    stack = [[]]
    depth = 0
    for tok in tokenize(src):
        if tok == '(':
            new = []; stack[-1].append(new); stack.append(new); depth += 1
        elif tok == ')':
            if depth == 0:
                raise SyntaxError('unbalanced ")"')
            stack.pop(); depth -= 1
        elif tok[0] == 'preproc':
            if keep_preproc: stack[-1].append(tok)
        else:
            stack[-1].append(tok[1])
    if depth:
        raise SyntaxError(f'{depth} unclosed "("')
    return stack[0]

def load(path, keep_preproc=False):
    with open(path, 'rb') as f:
        return parse(f.read().decode('latin-1'), keep_preproc)

def find(tree, key):
    """Yield the payload list following each occurrence of `key`.

    Reader files are KEY ( ... ) pairs, so the payload is the sibling
    immediately after the key atom.
    """
    if isinstance(tree, list):
        for a, b in zip(tree, tree[1:]):
            if a == key:
                yield b
        for node in tree:
            yield from find(node, key)

def demo():
    t = parse('; c\n( NAME ( "a b" ) N ( 1 -2 3.5 ) SYM ( foo ) EMPTY () )')
    assert t == [['NAME', ['a b'], 'N', [1, -2, 3.5], 'SYM', ['foo'], 'EMPTY', []]], t
    assert list(find(t, 'NAME')) == [['a b']]
    assert _atom('007', False) == 7 and _atom('007', True) == '007'
    assert _atom('1.5e3', False) == 1500.0
    assert _atom('m15obj6', False) == 'm15obj6'
    assert parse('#include "x"\n(A)') == [['A']]
    # bare '#' is a key label, not a directive (UiParams.rdr on-screen keyboard)
    assert parse('( Key ( # ) Key ( $ ) )') == [['Key', ['#'], 'Key', ['$']]]
    for bad in ('(', '())'):
        try: parse(bad); assert False, bad
        except SyntaxError: pass
    print('ok')

if __name__ == '__main__':
    if len(sys.argv) < 2: demo()
    else:
        import json
        print(json.dumps(load(sys.argv[1]), indent=1)[:4000])
