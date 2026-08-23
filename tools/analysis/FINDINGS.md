# Findings: the hardware seam, the renderer, and what a port has to build

Everything here is measured against the retail `SCUS_972.05`, not inferred from
general PS2 knowledge. Where a claim rests on a single observation, that is said.

## The hardware surface is 27 functions

Scanning every `lui`/load-store pair in the image against the EE register map,
exactly 27 functions touch hardware directly. Everything above that line is
ordinary memory manipulation — which is what the verified lifting already covers.

| layer | functions | size | port treatment |
|---|---|---|---|
| `zSysFifo*` | 5 | 872 B | rewrite — DMA kick and FIFO management |
| `zVid_*` | 15 | 3,832 B | rewrite — video mode, swap, scissor, z-test |
| `sceDma*` / `sceGifPk*` | 22 | 2,304 B | replace with host equivalents |
| `CPipe` | 19 | 13,900 B | port as-is — builds packets in plain memory |

`zSysFifoKick` is the single submission point, with 21 callers. That is the seam a
port cuts at.

Two corrections worth recording, because both are easy to get wrong:

- **`gsapi_*` is not graphics.** Those 58 functions (16 KB) are SpeechWorks voice
  recognition — SOCOM's headset commands. The `.SCC` / `.BNF` / `.CTX` / `.WRD`
  files on the disc are its grammars.
- **`sceGifPk*` is not the renderer's packet builder.** Its only callers are
  `sceDevFont` and `sceDevCons`, the SCE debug console overlay.

## The wire format

Running `SetGSReg` — the smallest complete packet builder in the image — inside the
interpreter and recording every store produces a real packet, in scratchpad at
`0x70000000`, built by the game's own code:

```
+00  10000002              DMA tag  — CNT, qwc = 2
+08  11000000  50000002    VIF      — FLUSH, then DIRECT of 2 quadwords
+10  1000000000008001      GIF tag  — nloop 1, eop, PACKED, nreg 1
+18  0e                    regs     — A+D
+20  ...0001   ...0047     payload  — TEST_1 = 1
```

So the path is VIF1 → DIRECT → GIF, the standard PS2 arrangement. `gs.py` was
written from the documented GIF layout beforehand and decodes these bytes
correctly, field for field — including the `nloop` arithmetic that
`sceGifPkCloseGifTag` performs in the ROM itself (FLG at bits 58–59, NREG at 60–63
with 0 meaning 16, NLOOP at 0–14, and the REGLIST-vs-PACKED divisor).

**There are no static display lists.** A scan for the full DMA+VIF+GIF signature
finds zero occurrences in the executable, against zero in an equal volume of random
bytes. The detector was validated against the captured packet first — a scanner
that finds nothing is otherwise indistinguishable from a broken one. Every display
list is generated at runtime.

An earlier attempt scanning for bare GIF tags produced 2,859 hits; a control run
showed it was matching MIPS instructions that happen to have the right bit pattern.
Requiring the whole wrapper is what made the signal real.

## VU0

Three `VCALLMS` opcodes remain unmodelled, blocking 46 functions. They are not a
reason to write a VU0 micro-mode interpreter — there are only four call sites, and
they are all math kernels:

| micromem | callers |
|---|---|
| `0x010` | `zdb::CDIPoly::GetIntersect` |
| `0x040` | `CBBox::GetIntersect`, `zdb::CDIBBox::GetIntersect` |
| `0x060` | `CQuat::Apply` |

Quaternion apply, AABB intersect, polygon intersect. Reimplement them.

The microcode itself has not been located: nothing writes the VU0 memory window at
`0x11000000`, so it is uploaded by VIF MPG over DMA. That means the three kernels
can be reimplemented but not differentially verified.

## Coverage is leaves, not spine

Walking down from `main`, only 18 of the first 65 functions have any verification
status. The spine — `zSysInit`, `COurGame::StartEngine`, `CGame::Tick` — is excluded
by construction, because it is exactly the code that talks to the operating system.

For a port this is the right way round. Leaf behaviour is expensive to get subtly
wrong and cheap to verify; the spine is rewrite territory regardless.

## Data tables recovered without decompiling

Several of the largest game functions are tables written as code. Replacing each
callee with an immediate return turns them into straight-line argument computation,
and the arguments are the table.

| function | size | recovered |
|---|---|---|
| `RegisterPackets` | 20,188 B | 159 network messages, 721 fields |
| `InitializeAnimNames` | 17,612 B | 156 animation names |

## Order of work for a port

1. **A GS translator behind `zSysFifoKick`.** Parse DMA tags and VIF codes, feed GIF
   packets to a GS layer over a modern API. The format is decoded; the seam is one
   function wide.
2. **Replace the platform spine.** `zSysInit`, threads, CD filesystem, IOP modules.
3. **Land the verified leaves.** 3,614 functions with a proven reference.
4. **Hand-port the 3,300 untestable functions.** The long pole — 1.5 MB, including
   the largest AI and animation routines, with no automated check available.
5. **Decode the asset payloads.** The ZAR container is solved and audio is standard
   RIFF/VAG, but the model and animation payloads are still opaque. Every model
   begins `01 01 00 01 00 80 04 6c`; it is not a `NODE_PARAMS` and not DMA-wrapped.

## Runtime structures the DWARF hands over

Useful for the port's data model — all exact, from the ROM:

- `TEXTURE_PARAMS` — width, height, `m_gsaddr`, and bitfields for `m_palettized`,
  `m_bumpmap`, `m_bilinear`, `m_transp_1bit`, `m_dynamic`
- `CTexture` — carries `m_TEX0`, `m_MIP1`, `m_MIP2` (actual GS register values) plus
  `m_gifSelect` / `m_vuSelect` packet fragments and `m_dmaRef` tags
- `tag_NODE_PARAMS` — `CMatrix` + `CBBox` + a 32-bit flag word broken out to
  individual bits (`m_shadow`, `m_reflective`, `m_scrolling_texture`,
  `m_mtx_is_identity`, …)

All 407 described classes are in `data/gamez_types.h`.

## Notes on the verifier itself

A verification result is worth what its verifier is worth, so three bugs found and
fixed in this tooling are recorded here:

- **Result-list truncation.** `difftest` compared `zip(expect, got)`; a driver that
  died partway had only its surviving prefix compared and was reported as a full
  pass. Eight false passes were found and demoted. The count is now checked before
  the values.
- **Branch into a delay slot.** Folding a delay slot into its branch consumed the
  address and dropped its label. Exactly one function in the image does this
  (`sceSifWriteBackDCache`), but it sits on the SIF DMA path, so it appeared in
  hundreds of call graphs.
- **Argument registers disagreed.** The lifted driver set `$a0`–`$a3` while the
  interpreter set only `$a0`/`$a1`. Every function reading a third parameter
  disagreed by construction — 112 of the 113 then-remaining mismatches. Note that
  the fix needs *small* distinct values: large ones read as array lengths and walk
  the interpreter past its step limit.

There is also an accounting trap worth knowing about: 66 names in this ROM belong to
more than one function (C++ overloads, plus statics with the same name in different
translation units). A name-keyed ledger silently loses 74 results and lets one
function's output overwrite another's. Key by address.
