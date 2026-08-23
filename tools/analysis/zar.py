"""Read Zipper's ZAR archives, using the layout the ROM's own debug info gives.

The ZAR files on the disc hold every model, texture, sound and tuning table, so
a port has to open them. The format did not need guessing: SCUS_972.05 carries
DWARF for zar::CZAR, and that pinned the structures; the remaining unknowns fell
out of arithmetic that has to balance on every file.

    file:  [ payload ][ string table ][ keys ][ TAIL ]

    TAIL   96 bytes, at the very end
        +00 flags       +04 key_count   +08 stable_size  +0c stable_ptr
        +10 reserved[64]
        +50 offset      +54 crc         +58 appversion   +5c version

    key    16 bytes each, key_count of them, immediately after the strings
        +00 name        +04 offset      +08 size         +0c children

`offset` in the TAIL is where the string table starts, and the keys follow it
directly -- so `offset + stable_size + key_count * 16` lands exactly on the
TAIL, which is the check that fixed the layout.

Two fields are stored as live pointers from the machine that wrote the file:
`stable_ptr` and each key's `name`. Neither is meaningful as an address, but
their difference is: `name - stable_ptr` indexes the string table. That
subtraction is what zar::CKey::fixupKey does at load time.

`children` makes the keys a tree rather than a flat list, matching CZAR's
m_root and CKeyRing members.

usage:
    python zar.py <file.zar>              # list it
    python zar.py --iso <iso>             # check every ZAR on a disc
    python zar.py <file.zar> --extract DIR
"""
import os, struct, sys

TAIL_LEN = 96
KEY_LEN = 16


class Tail:
    __slots__ = ('flags', 'key_count', 'stable_size', 'stable_ptr',
                 'offset', 'crc', 'appversion', 'version')

    def __init__(self, b):
        (self.flags, self.key_count, self.stable_size,
         self.stable_ptr) = struct.unpack_from('<4i', b, 0)
        (self.offset, self.crc, self.appversion,
         self.version) = struct.unpack_from('<4i', b, 0x50)

    def __repr__(self):
        return (f'TAIL(keys={self.key_count} strings={self.stable_size}B '
                f'dir@{self.offset:#x} ver={self.version:#x})')


class Key:
    __slots__ = ('name', 'offset', 'size', 'children')

    def __init__(self, name, offset, size, children):
        self.name, self.offset = name, offset
        self.size, self.children = size, children

    def __repr__(self):
        return (f'{self.name!r} @{self.offset} +{self.size}'
                + (f' ({self.children} children)' if self.children else ''))


def parse(blob):
    """-> (tail, [Key]). Raises ValueError if the file is not a ZAR."""
    if len(blob) < TAIL_LEN:
        raise ValueError('shorter than a TAIL')
    t = Tail(blob[-TAIL_LEN:])
    kbase = t.offset + t.stable_size
    end = len(blob) - TAIL_LEN
    if not (0 <= t.offset <= end and 0 <= t.stable_size
            and 0 <= t.key_count < (1 << 22)):
        raise ValueError(f'implausible tail: {t!r}')
    # The directory has to end exactly where the tail begins. This is the
    # whole reason the layout is known rather than assumed.
    if kbase + t.key_count * KEY_LEN != end:
        raise ValueError(
            f'directory does not close: {t.offset} + {t.stable_size} + '
            f'{t.key_count}*{KEY_LEN} = {kbase + t.key_count * KEY_LEN}, '
            f'expected {end}')
    stab = blob[t.offset:t.offset + t.stable_size]
    base = t.stable_ptr & 0xffffffff
    keys = []
    for i in range(t.key_count):
        nptr, off, size, kids = struct.unpack_from('<4I', blob,
                                                   kbase + i * KEY_LEN)
        idx = (nptr - base) & 0xffffffff
        if idx < len(stab):
            e = stab.find(b'\x00', idx)
            nm = stab[idx:e if e >= 0 else None].decode('latin-1', 'replace')
        else:
            nm = f'@{i}'
        keys.append(Key(nm, off, size, kids))
    return t, keys


def printable(k):
    return bool(k.name) and all(32 <= ord(c) < 127 for c in k.name)


def check(blob):
    """-> (tail, keys, how many keys look structurally sound)."""
    t, keys = parse(blob)
    lim = len(blob) - TAIL_LEN
    good = sum(1 for k in keys
               if printable(k) and k.offset + k.size <= lim)
    return t, keys, good


def selfcheck():
    """A hand-built archive must round-trip, and a broken one must be
    rejected rather than silently mis-parsed."""
    stab = b'\x00hello.bin\x00world.bin\x00'
    payload = b'A' * 32
    base = 0x10000000
    keys = b''
    for nm, off, size in (('hello.bin', 0, 16), ('world.bin', 16, 16)):
        keys += struct.pack('<4I', base + stab.index(nm.encode()), off, size, 0)
    body = payload + stab + keys
    tail = (struct.pack('<4i', 0, 2, len(stab), base)
            + b'\x00' * 64
            + struct.pack('<4i', len(payload), 0, -1, 0x20001))
    t, ks, good = check(body + tail)
    assert t.key_count == 2 and good == 2, (t, good)
    assert [k.name for k in ks] == ['hello.bin', 'world.bin'], ks
    assert (ks[1].offset, ks[1].size) == (16, 16), ks[1]
    # a directory that does not close must raise, not return garbage
    bad = struct.pack('<4i', 0, 3, len(stab), base) + b'\x00' * 64 \
        + struct.pack('<4i', len(payload), 0, -1, 0x20001)
    try:
        parse(body + bad)
    except ValueError:
        pass
    else:
        raise AssertionError('a malformed directory was accepted')
    print('selfcheck ok')


def iso_files(path):
    """Every file on an ISO9660 disc -> [(name, lba, size)]."""
    f = open(path, 'rb')
    SEC = 2048

    def rd(lba, size):
        f.seek(lba * SEC)
        d = f.read(size)
        i, out = 0, []
        while i < len(d):
            L = d[i]
            if L == 0:
                i = (i // SEC + 1) * SEC
                if i >= len(d):
                    break
                continue
            e = d[i:i + L]
            nl = e[32]
            out.append((e[33:33 + nl].decode('latin-1'),
                        struct.unpack('<I', e[2:6])[0],
                        struct.unpack('<I', e[10:14])[0], bool(e[25] & 2)))
            i += L
        return out

    f.seek(16 * SEC)
    root = f.read(SEC)[156:190]
    out = []

    def walk(es, p=''):
        for nm, l, s, isdir in es:
            if nm in ('\x00', '\x01'):
                continue
            if isdir:
                walk(rd(l, s), p + nm + '/')
            else:
                out.append((p + nm.split(';')[0], l, s))
    walk(rd(struct.unpack('<I', root[2:6])[0],
            struct.unpack('<I', root[10:14])[0]))
    return f, out


def main(argv):
    selfcheck()
    if not argv:
        return
    if argv[0] == '--iso':
        f, files = iso_files(argv[1])
        zars = [x for x in files if x[0].upper().endswith('.ZAR')]
        okf = tot = totgood = 0
        for nm, lba, size in zars:
            f.seek(lba * 2048)
            blob = f.read(size)
            try:
                t, keys, good = check(blob)
            except ValueError as ex:
                print(f'  FAIL {nm[:48]:48s} {ex}')
                continue
            okf += 1
            tot += len(keys)
            totgood += good
            if len(keys) > 8:
                print(f'  ok   {nm[:48]:48s} {len(keys):6,d} keys '
                      f'{good * 100 // max(len(keys), 1):3d}% sound')
        print(f'\n{okf}/{len(zars)} archives parsed, {tot:,} keys, '
              f'{totgood:,} ({100 * totgood // max(tot, 1)}%) with a printable '
              f'name and an in-range extent')
        return
    blob = open(argv[0], 'rb').read()
    t, keys, good = check(blob)
    print(t, f'-- {good}/{len(keys)} sound')
    for k in keys[:40]:
        print(f'  {k}')
    if '--extract' in argv:
        d = argv[argv.index('--extract') + 1]
        os.makedirs(d, exist_ok=True)
        n = 0
        for k in keys:
            if k.size and printable(k):
                safe = k.name.replace('/', '_').replace('\\', '_')
                open(os.path.join(d, safe), 'wb').write(
                    blob[k.offset:k.offset + k.size])
                n += 1
        print(f'extracted {n} entries to {d}/')


if __name__ == '__main__':
    main(sys.argv[1:])
