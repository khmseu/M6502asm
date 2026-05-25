# Plan: Translate M6502 asm to xa65

TL;DR: Create a Python-based translator that converts `m6502.asm` (MACRO-10/M6502 style) into xa65 v2.4.0-compatible source. The translator will aim for a full translation scope, preserve includes and file structure where possible, and produce warnings for constructs requiring manual review. Output will be suitable for assembling with xa65 v2.4.0. A git commit will be produced when changes are ready.

## Phases (5)

1. **Phase 1: Analyze syntax differences**
    - **Objective:** Identify syntactic and semantic differences between `m6502.asm` and xa65.
    - **Files/Functions to Modify/Create:** Read `BASIC-M6502/m6502.asm`, `test_dci.asm`, and `m6502asm.py` for parsing rules.
    - **Tests to Write:** None (research).
    - **Steps:**
        1. Catalog directives, macro forms, label styles, comment conventions, and expression formats.
        2. Note pseudo-ops (DCI/XWD/etc.) and expression quirks to replicate or pre-evaluate.
        3. Produce mapping recommendations.

2. **Phase 2: Design translator & test harness**
    - **Objective:** Design parsing/mapping approach and CLI.
    - **Files/Functions to Modify/Create:** `m6502_to_xa65.py` (skeleton), `tests/` placeholders, `plans/translate-m6502-to-xa65-phase-2-design.md`.
    - **Tests to Write:** `test_simple_instruction_conversion`, `test_directive_conversion`, `test_label_and_comment_preservation`.
    - **Steps:**
        1. Define opcode and directive mapping tables and macro translation rules.
        2. Decide between regex-based line transforms vs tokenization (recommend tokenization to handle `<...>` macro bodies).
        3. Design CLI: `--in`, `--out`, `--dry-run`, `--map-file`, `--preserve-includes`.

3. **Phase 3: Implement core translator**
    - **Objective:** Build a translator that handles main opcodes, directives, labels, comments, and core DEFINE->xa65 macro translation.
    - **Files/Functions to Modify/Create:** `m6502_to_xa65.py` (implementation), `tests/` (unit tests), `examples/` (converted samples).
    - **Tests to Write:** The tests from Phase 2 plus small round-trip checks on `test_dci.asm`.
    - **Steps:**
        1. Implement tokenizer for lines and angle-bracket bodies.
        2. Implement opcode/addressing mapping rules (e.g., `LDAI X` → `LDA #X`, `LDADY X` → `LDA (X),Y`, `JMPD X` → `JMP (X)`).
        3. Emit xa65-compatible directives (`.org`, `.byte`, `.word`, `.equ`) and preserve includes when possible.

4. **Phase 4: Extend for macros, includes, and edge-cases**
    - **Objective:** Convert complex `DEFINE` macros to xa65 macros or safe passthroughs; handle conditional directives or warn when manual fixes needed.
    - **Files/Functions to Modify/Create:** enhancements in `m6502_to_xa65.py`, more tests for macros/includes.
    - **Tests to Write:** `test_macro_conversion`, `test_include_handling`, `test_equ_conversion`.
    - **Steps:**
        1. Translate `DEFINE name,(params),<body>` to xa65 `macro` syntax where possible; otherwise emit a preserved body plus warnings.
        2. Map conditional constructs (`IF`, `IFE`, `IFN`) to safe xa65 equivalents or mark for review.
        3. Add symbol name mapping layer to avoid collisions (MACRO-10 uppercase + 6-char truncation differences).

5. **Phase 5: Documentation and examples**
    - **Objective:** Add README, usage examples, and sample converted files.
    - **Files/Functions to Modify/Create:** `README.md`, `examples/converted/`.
    - **Tests to Write:** None.
    - **Steps:**
        1. Document usage, limitations, and known manual-review areas.
        2. Provide example conversions and sample `xa65` assemble commands.

## Open Questions (answered)

1. Scope: Full translation (yes).
2. Output: Preserve includes and file structure where feasible (yes).
3. Target xa65: v2.4.0; assume feature flags when useful.
4. Language: Python accepted.
5. Auto-commit: Yes, produce git commit when ready.

## Progress Update

- Phase 2 completed: mapping/parser strategy documented in `plans/translate-m6502-to-xa65-phase-2-design.md`.
- Phase 3 started: initial `m6502_to_xa65.py` implementation and unit tests added.
- Phase 3 expanded: full-file translation pass on `BASIC-M6502/m6502.asm` now emits only one warning.
- Implemented: COMMENT block passthrough, DEFINE quote-pattern fix, trailing `>` conditional closer handling, `EXP` -> `.byte`, and `END` -> `.end` mapping.

## Next Steps

- Phase 4: convert remaining `IRPC`/`IFDIF` metaprogramming in `DT` macro to xa65-native macro logic.
- Phase 4: add symbol-collision mapping defaults and conflict-reporting in `--map-file` workflows.
- Add example converted outputs under `examples/converted/`.
