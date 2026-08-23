// po2  --  decompiled from SCUS_972.05 @ 0x002f9600 (172 bytes)
// mangled: po2__FUi   ->  po2(unsigned int)
//
// Maps a texture dimension to its PS2 log2 bucket. The ROM is a chain of
// sltiu/beqz with the result written in each branch's delay slot.
//
// Verified behaviourally against the ROM by difftest.py -- not byte-matched
// (that would need Metrowerks MIPS 2.4.1).

typedef unsigned int u32;

u32 po2(u32 n)
{
    if (n < 3)   return 1;
    if (n < 5)   return 2;
    if (n < 9)   return 3;
    if (n < 17)  return 4;
    if (n < 33)  return 5;
    if (n < 65)  return 6;
    if (n < 129) return 7;
    if (n < 257) return 8;
    if (n < 513) return 9;
    return 10;
}
