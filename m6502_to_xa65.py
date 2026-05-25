#!/usr/bin/env python3
"""Translate MACRO-10/M6502 style source into xa65-oriented assembly."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


IMM_MNEMONICS = {
    "LDAI": "LDA",
    "LDXI": "LDX",
    "LDYI": "LDY",
    "CMPI": "CMP",
    "CPXI": "CPX",
    "CPYI": "CPY",
    "ADCI": "ADC",
    "SBCI": "SBC",
    "ANDI": "AND",
    "ORAI": "ORA",
    "EORI": "EOR",
}

INY_MNEMONICS = {
    "LDADY": "LDA",
    "STADY": "STA",
    "ADCDY": "ADC",
    "SBCDY": "SBC",
    "CMPDY": "CMP",
    "ANDDY": "AND",
    "ORADY": "ORA",
    "EORDY": "EOR",
}


@dataclass
class TranslationResult:
    text: str
    warnings: list[str]


def split_comment(line: str) -> tuple[str, str]:
    in_quote = False
    for idx, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == ";" and not in_quote:
            return line[:idx], line[idx:]
    return line, ""


def angle_delta(line: str) -> int:
    code, _ = split_comment(line)
    delta = 0
    for ch in code:
        if ch == "<":
            delta += 1
        elif ch == ">":
            delta -= 1
    return delta


def find_matching_angle_block(text: str, start_idx: int) -> int:
    depth = 1
    idx = start_idx
    while idx < len(text):
        ch = text[idx]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return -1


class Translator:
    def __init__(self, symbol_map: dict[str, str] | None = None, preserve_includes: bool = False):
        self.symbol_map = symbol_map or {}
        self.preserve_includes = preserve_includes
        self.warnings: list[str] = []

    def map_symbol(self, symbol: str) -> str:
        return self.symbol_map.get(symbol, symbol)

    def translate(self, source: str) -> TranslationResult:
        lines = source.splitlines()
        out: list[str] = []
        idx = 0
        comment_block_delim: str | None = None

        while idx < len(lines):
            line = lines[idx]

            if comment_block_delim is not None:
                stripped = line.strip()
                out.append(f"; {line}" if line else ";")
                if stripped == comment_block_delim:
                    comment_block_delim = None
                idx += 1
                continue

            comment_open = re.match(r"^\s*COMMENT\s+(.+)\s*$", line, flags=re.IGNORECASE)
            if comment_open:
                delim = comment_open.group(1).strip()
                if delim:
                    comment_block_delim = delim
                out.append(f"; {line}" if line else ";")
                idx += 1
                continue

            if re.match(r"^\s*DEFINE\b", line, flags=re.IGNORECASE):
                block, consumed = self._consume_define_block(lines, idx)
                out.extend(block)
                idx += consumed
                continue

            out.extend(self._translate_line(line))
            idx += 1

        return TranslationResult(text="\n".join(out) + "\n", warnings=self.warnings)

    def _consume_define_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        collected: list[str] = []
        idx = start
        balance = 0
        started = False

        while idx < len(lines):
            ln = lines[idx]
            collected.append(ln)
            delta = angle_delta(ln)
            if "<" in split_comment(ln)[0]:
                started = True
            balance += delta
            idx += 1
            if started and balance <= 0:
                break

        joined = "\n".join(collected)
        m = re.search(r"DEFINE\s+", joined, flags=re.IGNORECASE)
        if not m:
            self.warnings.append("Unparsed DEFINE block; preserved as comments.")
            return ([f"; {line}" for line in collected], idx - start)

        header_start = m.start()
        first_lt = joined.find("<", header_start)
        if first_lt == -1:
            self.warnings.append("DEFINE without body; preserved as comments.")
            return ([f"; {line}" for line in collected], idx - start)

        header = joined[header_start:first_lt].strip()
        body_end = find_matching_angle_block(joined, first_lt + 1)
        if body_end == -1:
            self.warnings.append("Unbalanced DEFINE body; preserved as comments.")
            return ([f"; {line}" for line in collected], idx - start)

        body = joined[first_lt + 1 : body_end]
        header_match = re.match(
            r"^DEFINE\s+([A-Za-z_.$%#@][\w.$%#@]*)\s*(?:\(([^)]*)\))?\s*,\s*$",
            header,
            flags=re.IGNORECASE,
        )
        if not header_match:
            self.warnings.append(f"Could not parse DEFINE header: {header}")
            return ([f"; {line}" for line in collected], idx - start)

        name = self.map_symbol(header_match.group(1).strip())
        params_raw = (header_match.group(2) or "").strip()
        params = [self.map_symbol(p.strip()) for p in params_raw.split(",") if p.strip()]

        if name.upper() == "DT" and len(params) == 1:
            # DT expands text arguments into bytes; in xa65 a direct .byte on the
            # macro parameter preserves the intended call-site behavior.
            return [f".macro {name} {params[0]}", f".byte {params[0]}", ".endmacro"], idx - start

        out = [f".macro {name}{(' ' + ', '.join(params)) if params else ''}"]
        for body_line in body.splitlines():
            translated = self._translate_line(body_line)
            out.extend(translated if translated else [""])
        out.append(".endmacro")
        return out, idx - start

    def _if_expr(self, kind: str, expr: str) -> str:
        expr = expr.strip()
        if kind.upper() == "IFE":
            return f"({expr}) = 0"
        if kind.upper() == "IFN":
            return f"({expr}) <> 0"
        return expr

    def _split_trailing_endif_closers(self, stripped: str) -> tuple[str, int]:
        if not stripped or stripped == ">":
            return stripped, 0
        trailing = len(stripped) - len(stripped.rstrip(">"))
        if trailing == 0:
            return stripped, 0
        lt_count = stripped.count("<")
        gt_count = stripped.count(">")
        excess = gt_count - lt_count
        if excess <= 0:
            return stripped, 0
        close_count = min(excess, trailing)
        core = stripped[:-close_count].rstrip()
        return core, close_count

    def _looks_like_data_expr(self, text: str) -> bool:
        if not text or re.search(r"\s", text):
            return False
        if text[0] not in "0123456789-\"^<(":
            return False
        return re.fullmatch(r"[0-9A-Za-z_.$%#@\^\"<>()+\-*/&!,]+", text) is not None

    def _translate_line(self, line: str) -> list[str]:
        code, comment = split_comment(line)
        raw = code.rstrip()
        stripped = raw.strip()

        if stripped == "":
            return [comment if comment else ""]

        if re.fullmatch(r">+", stripped):
            return [".endif" for _ in stripped]

        stripped, trailing_endif_count = self._split_trailing_endif_closers(stripped)

        m_inline_if = re.match(r"^(IFE|IFN|IF)\s+(.+?),\s*<(.*)>\s*$", stripped, re.IGNORECASE)
        if m_inline_if:
            kind, expr, body = m_inline_if.groups()
            out = [f".if {self._if_expr(kind, expr)}"]
            out.extend(self._translate_line(body))
            out.append(".endif")
            out.extend([".endif"] * trailing_endif_count)
            return out

        m_open_if = re.match(r"^(IFE|IFN|IF)\s+(.+?),\s*<\s*$", stripped, re.IGNORECASE)
        if m_open_if:
            kind, expr = m_open_if.groups()
            out = [f".if {self._if_expr(kind, expr)}"]
            out.extend([".endif"] * trailing_endif_count)
            return out

        label_match = re.match(r"^([A-Za-z_.$%#@][\w.$%#@]*)(::?)\s*(.*)$", stripped)
        if label_match:
            label, _dbl, rest = label_match.groups()
            mapped = self.map_symbol(label)
            if rest:
                rest_out = self._translate_line(rest)
                if not rest_out:
                    return [f"{mapped}:" + (f" {comment}" if comment else "")]
                first = rest_out[0]
                rest_out[0] = f"{mapped}: {first}".rstrip()
                if comment:
                    rest_out[0] += f" {comment}"
                return rest_out
            return [f"{mapped}:" + (f" {comment}" if comment else "")]

        assign = re.match(r"^([A-Za-z_.$%#@][\w.$%#@]*)\s*(==|=)\s*(.+)$", stripped)
        if assign:
            sym, _eq, expr = assign.groups()
            out = [f"{self.map_symbol(sym)} .equ {expr.strip()}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        parts = stripped.split(None, 1)
        op = parts[0].upper()
        operand = parts[1].strip() if len(parts) > 1 else ""

        if op == "ORG":
            out = [f".org {operand}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op == "SEARCH":
            if self.preserve_includes and operand:
                include_name = operand.strip("<>").strip()
                out = [f'.include "{include_name}"' + (f" {comment}" if comment else "")]
                out.extend([".endif"] * trailing_endif_count)
                return out
            self.warnings.append(f"SEARCH directive left as comment: {stripped}")
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op in {"TITLE", "SUBTTL", "SALL", "PAGE", "RADIX", "PRINTX", "IF1"}:
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op == "END":
            out = [f".end {operand}".rstrip() + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op == "EXP":
            out = [f".byte {operand}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op in {"IRPC", "IFDIF"}:
            self.warnings.append(f"Directive requires manual review: {stripped}")
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op == "XWD":
            out = [f".word {operand}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        m_dci = re.match(r"^DCI\s*\"(.*)\"$", stripped, re.IGNORECASE)
        if m_dci:
            chars = m_dci.group(1)
            if not chars:
                out = [".byte 0"]
                out.extend([".endif"] * trailing_endif_count)
                return out
            encoded = [f"'{c}'" for c in chars[:-1]]
            encoded.append(f"'{chars[-1]}'|$80")
            out = [f".byte {', '.join(encoded)}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op in IMM_MNEMONICS:
            out = [f"{IMM_MNEMONICS[op]} #{operand}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op in INY_MNEMONICS:
            out = [f"{INY_MNEMONICS[op]} ({operand}),Y" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if op == "JMPD":
            out = [f"JMP ({operand})" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        if self._looks_like_data_expr(stripped):
            out = [f".byte {stripped}" + (f" {comment}" if comment else "")]
            out.extend([".endif"] * trailing_endif_count)
            return out

        out = [stripped + (f" {comment}" if comment else "")]
        out.extend([".endif"] * trailing_endif_count)
        return out


def load_symbol_map(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("Symbol map file must contain a JSON object.")
    return {str(k): str(v) for k, v in data.items()}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Translate M6502/MACRO-10 style assembly to xa65-style source.")
    parser.add_argument("input", nargs="?", help="Input source path.")
    parser.add_argument("--in", dest="in_file", help="Input source path.")
    parser.add_argument("--out", dest="out_file", help="Output path for translated source.")
    parser.add_argument("--dry-run", action="store_true", help="Write translated source to stdout.")
    parser.add_argument("--map-file", help="JSON map of old symbol names to new symbol names.")
    parser.add_argument("--preserve-includes", action="store_true", help="Convert SEARCH to .include.")
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
        out_path = Path(args.out_file) if args.out_file else src_path.with_suffix(".xa65.asm")
        out_path.write_text(result.text, encoding="utf-8")
        print(f"Wrote {out_path}")

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
