#!/usr/bin/env python3
"""Translate M6502/MACRO-10 style source to ca65-oriented assembly."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from m6502_to_xa65 import TranslationResult, Translator as XaTranslator, load_symbol_map

_DEFINE_RE = re.compile(r"^#define\s+([^\s]+)\s+(.+)$")
_NUMERIC_EXPR_RE = re.compile(r"^[0-9\s()+\-*/%&|^]+$")
_ORG_RE = re.compile(r"^(\s*)\*\s*=\s*(.+)$")
_BYT_RE = re.compile(r"^(\s*(?:[A-Za-z_.$%#@][\w.$%#@]*:\s*)?)\.byt\b", re.IGNORECASE)
_DSB_RE = re.compile(r"^(\s*(?:[A-Za-z_.$%#@][\w.$%#@]*:\s*)?)\.dsb\b", re.IGNORECASE)
_ASC_RE = re.compile(r"^(\s*(?:[A-Za-z_.$%#@][\w.$%#@]*:\s*)?)\.asc\s+", re.IGNORECASE)


def _rewrite_if_expr(expr: str) -> str:
    return expr.replace("!=", "<>").replace("==", "=")


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
    return line


def _rewrite_text_for_ca65(text: str) -> str:
    out_lines = [_rewrite_line_for_ca65(ln) for ln in text.splitlines()]
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
