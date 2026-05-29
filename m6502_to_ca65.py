#!/usr/bin/env python3
"""Translate M6502/MACRO-10 style source to ca65-oriented assembly."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from m6502_to_xa65 import _OPCODES, TranslationResult, Translator as XaTranslator, load_symbol_map

_DEFINE_RE = re.compile(r"^#define\s+([^\s]+)\s+(.+)$")
_NUMERIC_EXPR_RE = re.compile(r"^[0-9\s()+\-*/%&|^]+$")
_ORG_RE = re.compile(r"^(\s*)\*\s*=\s*(.+)$")
_BYT_RE = re.compile(r"^(\s*(?:[A-Za-z_.$%#@][\w.$%#@]*:\s*)?)\.byt\b", re.IGNORECASE)
_DSB_RE = re.compile(r"^(\s*(?:[A-Za-z_.$%#@][\w.$%#@]*:\s*)?)\.dsb\b", re.IGNORECASE)
_ASC_RE = re.compile(r"^(\s*(?:[A-Za-z_.$%#@][\w.$%#@]*:\s*)?)\.asc\s+", re.IGNORECASE)
_LABEL_RE = re.compile(r"^\s*([A-Za-z_.$%#@][\w.$%#@]*):")
_CA65_DEFINE_RE = re.compile(r"^\s*\.define\s+([A-Za-z_.$%#@][\w.$%#@]*)")
_CA65_SET_RE = re.compile(r"^\s*([A-Za-z_.$%#@][\w.$%#@]*)\s+\.set\b")
_SINGLE_CHAR_DQ_RE = re.compile(r'"([^"\\])"')
_REPEAT_START_RE = re.compile(r"^\s*REPEAT\s+(.+?)(?:,)?\s*$", re.IGNORECASE)
_ENDIF_RE = re.compile(r"^\s*\.endif\s*$", re.IGNORECASE)
_IF_RE = re.compile(r"^\s*\.if\s+(.+)$", re.IGNORECASE)
_IDENT_RE = re.compile(r"\b[A-Za-z_.$%#@][\w.$%#@]*\b")


def _rewrite_if_expr(expr: str) -> str:
    return expr.replace("!=", "<>").replace("==", "=")


def _rewrite_single_char_dq(line: str) -> str:
    def repl(m: re.Match[str]) -> str:
        c = m.group(1)
        return "39" if c == "'" else f"'{c}'"

    return _SINGLE_CHAR_DQ_RE.sub(repl, line)


def _strip_trailing_operand_comma(line: str) -> str:
    code, sep, comment = line.partition(";")
    code = re.sub(r",\s*$", "", code)
    if not sep:
        return code
    return f"{code};{comment}"


def _coerce_parenthesized_immediate_low_byte(line: str) -> str:
    # ca65 enforces 8-bit immediates. The source frequently uses parenthesized
    # expressions where the low byte is intended.
    out = line.replace("#(", "#<(")
    # If arithmetic continues after the closing paren, ensure the `<` applies
    # to the whole expression, not just the first parenthesized term.
    out = re.sub(r"#<\(([^)]+)\)\s*([+\-*/&|])\s*([^\s,;]+)", r"#<((\1)\2\3)", out)
    return out


def _comment_non_6502_mnemonics(line: str) -> str:
    code, sep, comment = line.partition(";")
    stripped = code.strip()
    if not stripped:
        return line

    m_label = _LABEL_RE.match(stripped)
    if m_label:
        stripped = stripped[m_label.end() :].strip()
        if not stripped:
            return line

    head = stripped.split(None, 1)[0]
    if head.startswith("."):
        return line

    if head.upper() == "REPEAT":
        return line

    # Comment out clearly non-6502 mnemonics (e.g. HRRZ/JRST) that appear in
    # target-specific branches and would otherwise break ca65 parsing.
    if re.fullmatch(r"[A-Z][A-Z0-9]{2,}", head) and head.upper() not in _OPCODES:
        return "; " + line
    return line


def _rewrite_line_for_ca65(line: str) -> str:
    if line.startswith("#ifdef "):
        return ".ifdef " + line[len("#ifdef ") :]
    if line.startswith("#ifndef "):
        return ".ifndef " + line[len("#ifndef ") :]
    if line.startswith("#if "):
        return ".if " + _rewrite_if_expr(line[len("#if ") :])
    if line.strip() == "#endif":
        return line.replace("#endif", ".endif", 1)

    org_match = _ORG_RE.match(line)
    if org_match:
        indent = org_match.group(1)
        rest = org_match.group(2)
        return f"{indent}.org {rest}"

    define_match = _DEFINE_RE.match(line)
    if define_match:
        name = define_match.group(1)
        body = define_match.group(2)
        # Function-like defines are kept as `.define` to avoid losing arity.
        if "(" in name and name.endswith(")"):
            return f".define {name} {body}"
        # Use redefinable `.set` for numeric expressions and `.define` for
        # symbolic aliases that may rely on forward references.
        if _NUMERIC_EXPR_RE.fullmatch(body):
            return f"{name} .set {body}"
        return f".define {name} {body}"

    line = _BYT_RE.sub(r"\1.byte", line)
    line = _DSB_RE.sub(r"\1.res", line)
    line = _ASC_RE.sub(r"\1.byte ", line)
    line = _rewrite_single_char_dq(line)
    line = _coerce_parenthesized_immediate_low_byte(line)
    line = _strip_trailing_operand_comma(line)
    line = _comment_non_6502_mnemonics(line)
    return line


def _rewrite_text_for_ca65(text: str) -> str:
    rewritten_lines = [_rewrite_line_for_ca65(src_line) for src_line in text.splitlines()]

    label_names: set[str] = set()
    for line in rewritten_lines:
        label_match = _LABEL_RE.match(line)
        if label_match:
            label_names.add(label_match.group(1))

    out_lines: list[str] = []
    active_macro_aliases: set[str] = set()
    known_constant_symbols: set[str] = set()
    pending_repeat_closers = 0

    for line in rewritten_lines:
        repeat_match = _REPEAT_START_RE.match(line)
        if repeat_match:
            line = f".repeat {repeat_match.group(1).strip()}"
            pending_repeat_closers += 1
        elif pending_repeat_closers > 0 and _ENDIF_RE.match(line):
            line = ".endrepeat"
            pending_repeat_closers -= 1

        set_match = _CA65_SET_RE.match(line)
        if set_match and set_match.group(1) in label_names:
            continue

        define_match = _CA65_DEFINE_RE.match(line)
        if define_match and define_match.group(1) in label_names:
            continue

        label_match = _LABEL_RE.match(line)
        if label_match:
            label = label_match.group(1)
            if label in active_macro_aliases:
                out_lines.append(f".undef {label}")
                active_macro_aliases.remove(label)

        if set_match:
            name = set_match.group(1)
            if name in active_macro_aliases:
                out_lines.append(f".undef {name}")
                active_macro_aliases.remove(name)
            known_constant_symbols.add(name)

        if define_match:
            name = define_match.group(1)
            if name in active_macro_aliases:
                out_lines.append(f".undef {name}")
            active_macro_aliases.add(name)

        if_match = _IF_RE.match(line)
        if if_match:
            expr = if_match.group(1)
            unresolved = [
                tok
                for tok in _IDENT_RE.findall(expr)
                if tok not in known_constant_symbols and tok.lower() != "defined"
            ]
            if unresolved:
                line = f".if 0 ; unresolved .if expression for ca65: {expr}"

        out_lines.append(line)

    return "\n".join(out_lines) + "\n"


class Translator:
    def __init__(self, symbol_map: dict[str, str] | None = None, preserve_includes: bool = False):
        self._xa = XaTranslator(symbol_map=symbol_map, preserve_includes=preserve_includes)

    def translate(self, source: str) -> TranslationResult:
        xa_result = self._xa.translate(source)
        return TranslationResult(
            text=_rewrite_text_for_ca65(xa_result.text),
            warnings=xa_result.warnings,
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Translate M6502/MACRO-10 style assembly to ca65-style source.")
    parser.add_argument("input", nargs="?", help="Input source path.")
    parser.add_argument("--in", dest="in_file", help="Input source path.")
    parser.add_argument("--out", dest="out_file", help="Output path for translated source.")
    parser.add_argument("--dry-run", action="store_true", help="Write translated source to stdout.")
    parser.add_argument("--map-file", help="JSON map of old symbol names to new symbol names.")
    parser.add_argument("--preserve-includes", action="store_true", help="Convert SEARCH to .include.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero exit code if translation emits any warnings.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    in_path = args.in_file or args.input
    if not in_path:
        print("error: provide input path as positional arg or --in", file=sys.stderr)
        return 2

    src_path = Path(in_path)
    text = src_path.read_text(encoding="utf-8")
    symbol_map = load_symbol_map(args.map_file)
    translator = Translator(symbol_map=symbol_map, preserve_includes=args.preserve_includes)
    result = translator.translate(text)

    if args.dry_run:
        sys.stdout.write(result.text)
    else:
        out_path = Path(args.out_file) if args.out_file else src_path.with_suffix(".ca65.asm")
        out_path.write_text(result.text, encoding="utf-8")
        print(f"Wrote {out_path}")

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    if args.strict and result.warnings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
