# M6502asm Translator Notes

This repository now includes a translator for converting Microsoft BASIC MACRO-10/M6502 source into xa65-style source.

## Translator Script

- Script: `m6502_to_xa65.py`
- Input style: MACRO-10/M6502 assembly (`DEFINE`, `IFE/IFN/IF`, `DCI`, M6502 shorthand opcodes)
- Output style: xa65-oriented assembly (`.macro`, `.if/.endif`, `.byte`, `.word`, `.org`, `.equ`)

## Usage

Translate a file and write output next to the input:

```bash
python3 m6502_to_xa65.py --in BASIC-M6502/m6502.asm --preserve-includes
```

Write to an explicit output path:

```bash
python3 m6502_to_xa65.py \
  --in BASIC-M6502/m6502.asm \
  --out examples/converted/m6502_xa65.asm \
  --preserve-includes
```

Preview translated output to stdout:

```bash
python3 m6502_to_xa65.py --in test_dci.asm --dry-run
```

Enable strict mode (non-zero exit code if warnings are emitted):

```bash
python3 m6502_to_xa65.py --in BASIC-M6502/m6502.asm --strict
```

## Options

- `--in`: input source path
- `--out`: output source path (default: `<input>.xa65.asm`)
- `--dry-run`: write translation to stdout
- `--map-file`: JSON symbol rename map
- `--preserve-includes`: map `SEARCH name` to `.include "name"`
- `--strict`: fail with exit code 1 if warnings occur

## Validation

Run translator tests:

```bash
python3 -m unittest discover -s tests -v
```

## Current Coverage

The translator currently handles:

- Core opcode shorthand mappings (for example `LDAI`, `LDADY`, `JMPD`)
- `DEFINE` macro translation into xa65 `.macro` blocks
- `IFE`/`IFN`/`IF` conversion and trailing `>` closer handling
- `DCI`, `XWD`, `ORG`, symbol assignments (`=` and `==`), `EXP`, and `END`
- COMMENT-delimited text blocks as commented passthrough lines

## Known Limits

A small number of metaprogramming constructs may still require manual review in other source variants.
Use `--strict` in CI or automated checks to detect such cases.

When `--map-file` is used, the translator also emits a warning if multiple source symbols map to the same output symbol.
