# reCOM analysis tooling — verified decompilation of SCUS_972.05

Tooling and ground-truth data extracted from the SOCOM: U.S. Navy SEALs retail
executable, offered to [reCOM](https://github.com/NotEnoughPhotons/reCOM).

**No game files are included here** and none are needed to read the data. The
tools require you to supply your own `SCUS_972.05`.

## What this is

A pipeline that decompiles R5900 machine code and then *proves* each result
against the original, rather than eyeballing it:

```
ELF + DWARF  ->  lift.py     ->  C++
                 emu.py      ->  R5900 interpreter
                 difftest.py ->  run both over 400 random object states,
                                 compare return value AND the whole object image
```

A function is only recorded as verified when every case matches. Current state,
against the retail ELF:

| | functions | bytes |
|---|---|---|
| game functions in the ROM | 7,275 | 2,517,804 |
| differentially testable | 3,939 | 1,012,004 |
| **verified against the ROM** | **3,614** | **839,364** |

That is 92% of everything the technique can reach. The remaining 3,300 game
functions touch threads, the CD drive or DMA hardware, so an interpreter cannot
run them and they can never be proven this way — they need hand-porting.

## Ground-truth data (`data/`)

| file | what it is |
|---|---|
| `gamez_types.h` | 407 class layouts read out of the ROM's DWARF v1 — exact offsets, sizes and bitfields |
| `net_schema.json` | 159 Medius network messages, 721 fields, recovered from `RegisterPackets` |
| `anim_names.json` | 156 animation names in table order, from `InitializeAnimNames` |
| `lift_ledger.json` | per-function verification record, keyed by address |
| `worklist.json` | every function the harness can judge, with object sizes |

`gamez_types.h` is the most directly useful file here: it is the authoritative
answer to "what are the members of this class and where do they sit".

## Tools

**Reading the ROM**

- `symbols.py` — ELF sections, symtab, Metrowerks demangler
- `dwarf1.py` — DWARF v1 parser (Metrowerks); 116,691 records, no decode failures
- `disasm.py` — per-function work order: disassembly with call targets, globals and
  string literals resolved
- `origin.py` — splits the image by authorship (Zipper / MSL / SCE / C runtime)
- `audit.py` — compares reCOM's headers against the ROM's own type info
- `spine.py`, `callers.py` — call graph, annotated with what is verified

**Verifying**

- `emu.py` — R5900 interpreter: MMI, VU0 macro mode, 128-bit `lq`/`sq`, the EE FPU's
  non-IEEE behaviour (no Inf/NaN, chop rounding, ±FLT_MAX saturation)
- `lift.py` — MIPS → C++ transliterator with jump-table recovery and profiled
  indirect dispatch
- `difftest.py` — the verifier
- `bulk_lift.py` — batch driver
- `vu_xcheck.py` — random VU sequences through both models, compared at ULP level
- `verify_all.py` — regression gate

**Graphics and assets**

- `gs.py` — GIF tag / GS packet decoder
- `gs_rom_test.py` — captures a real packet by running `SetGSReg` in the interpreter,
  then decodes it. This is what validates `gs.py` against the game rather than
  against the documentation.
- `gs_survey.py` — which GS registers the renderer actually writes
- `hwmap.py` — every function touching EE hardware registers (there are 27)
- `dmascan.py` — DMA+VIF+GIF wrapper scanner, with a control run on random bytes
- `zar.py` — ZAR archive reader (see below)
- `tablex.py` — extracts data from registration functions by stubbing their callees

**Data files**

- `zrdr.py` — zReader `.rdr` parser, transcribed from reCOM's own `zrdr_parse.cpp`

## ZAR archives

`zar.py` reads every ZAR on the disc. The format came out of the ROM's DWARF for
`zar::CZAR` plus arithmetic that has to balance on every file:

```
file:  [ payload ][ string table ][ keys ][ TAIL 96 ]

TAIL   +00 flags   +04 key_count  +08 stable_size  +0c stable_ptr
       +50 offset  +54 crc        +58 appversion   +5c version
key    +00 name    +04 offset     +08 size         +0c children   (16 bytes)
```

`stable_ptr` and each key's `name` are stored as live pointers from the machine
that authored the file. Neither is a usable address, but `name - stable_ptr`
indexes the string table — which is exactly what `zar::CKey::fixupKey` repairs at
load time.

Validation: **76/76 archives parse, 62,196 keys, 100% with a printable name and an
extent inside the file.** As an independent check, an extracted `VM09_01.wav`
declares 95,984 bytes in its own RIFF header and its ZAR key says 95,984.

```
python zar.py --iso /path/to/socom.iso
python zar.py RUN/ZWEAPON.ZAR --extract out/
```

## Usage

```
pip install capstone ziglang
python disasm.py SCUS_972.05 CFader::SetMinBrightness   # work order
python lift.py   SCUS_972.05 0x2c8f10 160 > out.cpp     # lift
python difftest.py SCUS_972.05 0x2c8f10 out.cpp --obj=160
python verify_all.py                                    # regression gate
```

`ziglang` supplies the C++ compiler so no toolchain setup is needed.

## Caveats

- Verification covers the paths random object states reach. A function whose error
  handling never triggers is verified on its normal path only.
- Two independently written models can still be wrong in the same way. `vu_xcheck.py`
  and cross-checking hardware behaviour against PCSX2 documentation mitigate this;
  they do not eliminate it.
- The lifted C++ in `lift.py`'s output is register-machine code with `goto`s. It is
  not meant to be merged as-is — its value is being a *known-correct reference* for a
  human rewrite to check itself against.
- `methods/` holds hand-written decompilations that are both readable and verified.

See [FINDINGS.md](FINDINGS.md) for the renderer and hardware analysis.

All commands are run from this directory (`tools/analysis/`).
