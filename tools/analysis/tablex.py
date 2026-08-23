"""Extract the data hidden inside the game's big registration functions.

Several of the largest GAME functions are not logic at all -- they are tables
written as code. RegisterPackets is 20 KB of NetMessageField calls that
together define the multiplayer wire format; InitializeAnimNames is 17 KB of
string/index pairs. They are too big and too stateful for differential
testing, so they sit outside the worklist, yet what they contain is exactly
what a port needs as *data*.

Rather than decompile them, run them and write down what they say. Each
callee is replaced by an immediate return, so the function becomes pure
straight-line argument computation with no heap, no syscalls and no library
behaviour to model -- and the arguments are the table.

Callees are stubbed by rewriting the instruction stream, not by touching the
interpreter, so nothing here can perturb emu.py.

usage: python tablex.py <SCUS_972.05> <FunctionName>
"""
import collections, sys
from disasm import Image
from emu import Emu, Machine, Unsupported
from symbols import demangle


class StubMachine(Machine):
    """A Machine that makes chosen functions return immediately, and records
    the argument registers at the moment each one is entered."""

    def __init__(self, img, stubs, ret0=False):
        super().__init__(img)
        self.stubs = stubs                 # {entry addr: name}
        self.emu = None
        self.log = []
        # A stub leaves $v0 holding whatever was there before, so a loop
        # written as `while ((p = Next()))` never ends. Forcing a null return
        # terminates those, at the cost of not walking any list the real
        # callee would have produced.
        self.ret0 = ret0

    def ins(self, pc):
        if pc in self.stubs:
            e = self.emu
            self.log.append((self.stubs[pc],
                             [e.g32(f'$a{i}') for i in range(4)] if e else []))
            if e and self.ret0:
                e.set('$v0', 0)
            return ('jr', '$ra')
        if pc - 4 in self.stubs:           # the stub's delay slot
            return ('nop', '')
        return super().ins(pc)


def callees(img, addr, size):
    """Direct call targets of one function."""
    import struct
    out = {}
    for pc in range(addr, addr + size, 4):
        w = img.read(pc, 4)
        if len(w) < 4:
            break
        word, = struct.unpack('<I', w)
        if word >> 26 == 3:                                   # jal
            t = ((pc + 4) & 0xf0000000) | ((word & 0x03ffffff) << 2)
            if t in img.byaddr:
                c, m = demangle(img.byaddr[t][0])
                out[t] = f'{c}::{m}' if c else m
    return out


def extract(elf, func, limit=4000000, ret0=False):
    img = Image(elf)
    sym, addr, size = img.func(func)
    stubs = callees(img, addr, size)
    m = StubMachine(img, stubs, ret0)
    e = Emu(img, m)
    m.emu = e
    try:
        e.run(addr, size, [0, 0, 0, 0], [0.0], limit=limit)
    except Unsupported as ex:
        print(f'(stopped early: {ex})')
    return img, m.log


if __name__ == '__main__':
    elf = sys.argv[1] if len(sys.argv) > 1 else 'disc/SCUS_972.05'
    fn = sys.argv[2] if len(sys.argv) > 2 else 'RegisterPackets'
    img, log = extract(elf, fn)
    c = collections.Counter(n for n, _a in log)
    print(f'{fn}: {len(log)} calls captured\n')
    for k, n in c.most_common(12):
        print(f'  {n:5d}  {k[:70]}')
    print('\nfirst 30 calls with arguments:')
    for n, a in log[:30]:
        s = img.cstring(a[1]) if a and a[1] else None
        extra = f'   "{s}"' if s else ''
        print(f'  {n[:38]:38s} '
              + ' '.join(f'{x:>10x}' for x in a) + extra)


def netschema(elf='disc/SCUS_972.05'):
    """RegisterPackets -> the multiplayer wire format, as data.

    NetMessageField(base, field, elemsize, count) gives each field's offset
    from the message base, its element size and its array length.
    NetRegisterMessage(idslot, ?, handler, ?) closes a message off.
    """
    img, log = extract(elf, 'RegisterPackets')
    msgs, cur = [], []
    for name, a in log:
        if name == 'NetMessageField':
            base, fld, sz, n = a
            cur.append({'offset': fld - base, 'size': sz, 'count': n,
                        'bytes': sz * n})
        elif name == 'NetRegisterMessage':
            handler = img.label(a[2]) or f'0x{a[2]:08x}'
            msgs.append({'id_slot': f'0x{a[0]:08x}', 'handler': handler,
                         'fields': cur, 'bytes': sum(f['bytes'] for f in cur)})
            cur = []
    return msgs
