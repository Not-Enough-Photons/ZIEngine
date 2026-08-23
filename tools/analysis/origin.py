"""Split SCUS_972.05's 9,703 functions by who wrote them.

Not all of the ELF is Zipper's game. It also links the Metrowerks C++ standard
library, the SCE PS2 runtime, Sony's push-to-talk voice middleware and a
public-domain LPC-10 speech codec. Only the game part is decompilation work,
so progress percentages taken against the full 9,703 understate real coverage.

usage: python origin.py <SCUS_972.05>
"""
import collections, re, sys
from symbols import functions, demangle

# LPC-10 speech codec translation units, from the .debug file list
LPC10 = {
    'analys', 'bsynz', 'chanwr', 'dcbias', 'decode', 'deemp', 'difmag', 'dyptrk',
    'encode', 'energy', 'f2clib', 'ham84', 'hp100', 'invert', 'irc2pc', 'ivfilt',
    'lpcdec', 'lpcenc', 'lpcini', 'lpfilt', 'median', 'mload', 'onset', 'pitsyn',
    'placea', 'placev', 'preemp', 'prepro', 'random', 'rcchk', 'synths', 'tbdm',
    'voicin', 'vparms',
}


def origin(sym, cls, meth):
    name = f'{cls}::{meth}' if cls else meth
    if sym.startswith('__') and ('std' in sym or 'Q23std' in sym):
        return 'MSL C++ stdlib'
    if cls and (cls.startswith('std::') or cls == 'std' or 'Q23std' in sym):
        return 'MSL C++ stdlib'
    if re.match(r'^(std|__rs|__ls|__nw|__dl|__ct__Q23std)', name):
        return 'MSL C++ stdlib'
    if re.match(r'^_?sce', name) or 'sceSif' in name:
        return 'SCE PS2 runtime'
    if re.match(r'^(rt_|qEn|qDe|SlidingHisto|DynProg|SHSTransform)', name):
        return 'PTT voice middleware'
    if re.match(r'^(ptt|libptt)', name, re.I):
        return 'PTT voice middleware'
    base = re.sub(r'_+$', '', meth.split('_')[0]).lower()
    if base in LPC10 or meth.lower() in LPC10:
        return 'LPC-10 codec'
    if re.match(r'^(mem|str|spr|snprintf|printf|malloc|free|calloc|realloc|'
                r'abs|atof|atoi|qsort|rand|srand|toupper|tolower|isa|isd|iss)',
                name) and not cls:
        return 'C runtime'
    if re.match(r'^(Medius|cb[A-Z])', name):
        return 'Medius netcode'
    return 'GAME (Zipper)'


def main(elf):
    fs = functions(elf)
    by = collections.Counter()
    bybytes = collections.Counter()
    for sym, _a, size in fs:
        cls, meth = demangle(sym)
        o = origin(sym, cls, meth)
        by[o] += 1
        bybytes[o] += size
    tot, totb = len(fs), sum(s for _x, _y, s in fs)
    print(f'{"origin":24s}{"funcs":>7s}{"pct":>7s}{"bytes":>11s}{"pct":>7s}')
    for o, n in by.most_common():
        print(f'{o:24s}{n:7d}{100*n/tot:6.1f}%{bybytes[o]:11,d}{100*bybytes[o]/totb:6.1f}%')
    g, gb = by['GAME (Zipper)'], bybytes['GAME (Zipper)']
    print(f'\nreal decompilation target: {g:,} functions / {gb:,} bytes')
    print(f'(vs {tot:,} / {totb:,} if you count everything in the ELF)')
    return g, gb


def demo():
    assert origin('sync__Q23std15basic_streambuf', 'std::basic_streambuf',
                  'sync') == 'MSL C++ stdlib'
    assert origin('_sceSifLoadElfPart', None, '_sceSifLoadElfPart') == 'SCE PS2 runtime'
    assert origin('rt_msg_util_assert', None, 'rt_msg_util_assert') == 'PTT voice middleware'
    assert origin('voicin', None, 'voicin') == 'LPC-10 codec'
    assert origin('RenderNode__5CPipe', 'CPipe', 'RenderNode') == 'GAME (Zipper)'
    assert origin('Parse__9AI_PARAMS', 'AI_PARAMS', 'Parse') == 'GAME (Zipper)'
    print('ok')


if __name__ == '__main__':
    demo() if len(sys.argv) < 2 else main(sys.argv[1])
