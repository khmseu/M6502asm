# Phase 2 Design: M6502 to xa65 Translator

## Goals

- Translate core M6502/MACRO-10 style source into xa65-friendly syntax.
- Preserve source layout and comments as much as possible.
- Emit warnings for constructs that need manual inspection.

## Parsing Strategy

- Use a line-oriented translator with targeted token parsing.
- Use block collection for `DEFINE ... , <...>` bodies, including multiline forms.
- Use a lightweight splitter that keeps comments (`; ...`) intact.

## Core Mapping Rules

- Opcode shorthands:
- `LDAI X` -> `LDA #X`
- `LDADY X` -> `LDA (X),Y`
- `JMPD X` -> `JMP (X)`
- Directives:
- `ORG expr` -> `.org expr`
- `SYM=expr` / `SYM==expr` -> `SYM .equ expr`
- `XWD a,b` -> `.word a,b`
- `DCI"TEXT"` -> `.byte` list with last byte high-bit tagged.
- Includes:
- `SEARCH name` -> `.include "name"` when `--preserve-includes` is enabled.

## Macro Strategy

- Convert `DEFINE NAME(P1,P2),<body>` to:
- `.macro NAME P1, P2`
- translated body lines
- `.endmacro`
- If parsing fails, preserve source as comments and emit warning.

## Conditional Strategy

- Convert one-line and multiline forms:
- `IF expr,<...>` -> `.if expr`
- `IFE expr,<...>` -> `.if (expr) = 0`
- `IFN expr,<...>` -> `.if (expr) <> 0`
- trailing `>` closers -> `.endif`

## CLI

- `--in`, `--out`, `--dry-run`, `--map-file`, `--preserve-includes`
- Also accepts positional input path for convenience.

## Testing Approach

- Unit tests for:
- instruction conversion,
- directive conversion,
- label/comment preservation,
- macro conversion,
- include handling,
- DCI conversion.
