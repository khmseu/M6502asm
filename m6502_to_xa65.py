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

_RADIX_OCT_RE = re.compile(r"\^O([0-7]+)", re.IGNORECASE)
_RADIX_HEX_RE = re.compile(r"\^X([0-9A-F]+)", re.IGNORECASE)
_RADIX_DEC_RE = re.compile(r"\^D([0-9]+)", re.IGNORECASE)
_SYMBOL_TOKEN_RE = re.compile(r"\b[A-Za-z_.$%#@][\w.$%#@]*\b")


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
        self._mapped_symbol_owner: dict[str, str] = {}
        self._emitted_collision_keys: set[tuple[str, str, str]] = set()

    def _sanitize_symbol(self, symbol: str) -> str:
        mapped = re.sub(r"[^A-Za-z0-9_]", "_", symbol)
        if not mapped:
            return "_"
        if not re.match(r"^[A-Za-z_]", mapped):
            mapped = f"_{mapped}"
        return mapped

    def _normalize_expr(self, expr: str) -> str:
        out = _RADIX_OCT_RE.sub(lambda m: str(int(m.group(1), 8)), expr)
        out = _RADIX_HEX_RE.sub(lambda m: str(int(m.group(1), 16)), out)
        out = _RADIX_DEC_RE.sub(lambda m: m.group(1), out)
        out = _SYMBOL_TOKEN_RE.sub(lambda m: self.map_symbol(m.group(0)), out)
        return out

    def map_symbol(self, symbol: str) -> str:
        mapped = self.symbol_map.get(symbol, symbol)
        mapped = self._sanitize_symbol(mapped)
        owner = self._mapped_symbol_owner.get(mapped)
        if owner is None:
            self._mapped_symbol_owner[mapped] = symbol
            return mapped
        if owner != symbol:
            pair = tuple(sorted((owner, symbol)))
            key = (mapped, pair[0], pair[1])
            if key not in self._emitted_collision_keys:
                self._emitted_collision_keys.add(key)
                self.warnings.append(
                    f"Symbol mapping collision: {pair[0]} and {pair[1]} both map to {mapped}"
                )
        return mapped

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

            if re.match(r"^\s*(IFE|IFN|IF)\b", line, flags=re.IGNORECASE):
                block, consumed = self._consume_if_block(lines, idx)
                if consumed > 0:
                    out.extend(block)
                    idx += consumed
                    continue

            if re.match(r"^\s*IF[12]\s*,\s*<", line, flags=re.IGNORECASE):
                block, consumed = self._consume_pass_if_block(lines, idx)
                if consumed > 0:
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
            # DT is representable as a simple function-like preprocessor macro.
            return [f"#define {name}({params[0]}) .byt {params[0]}"], idx - start

        body_statements: list[str] = []
        for body_line in body.splitlines():
            translated = self._translate_line(body_line)
            for stmt in translated:
                stmt_code, _stmt_comment = split_comment(stmt)
                cleaned = stmt_code.strip()
                if cleaned:
                    body_statements.append(cleaned)

        wrapped = f".(:{':'.join(body_statements)}:.)" if body_statements else ".(:.)"
        if params:
            out = [f"#define {name}({', '.join(params)}) {wrapped}"]
        else:
            out = [f"#define {name} {wrapped}"]
        return out, idx - start

    def _consume_pass_if_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        code0, _ = split_comment(lines[start])
        m = re.match(r"^\s*IF([12])\s*,\s*<(.*)$", code0.strip(), re.IGNORECASE)
        if not m:
            return [], 0

        pass_num = m.group(1)
        after_lt = m.group(2)
        collected = [after_lt]
        idx = start + 1
        balance = 1 + after_lt.count("<") - after_lt.count(">")

        while idx < len(lines) and balance > 0:
            code_i, _ = split_comment(lines[idx])
            piece = code_i.rstrip()
            collected.append(piece)
            balance += piece.count("<") - piece.count(">")
            idx += 1

        joined = "\n".join(collected)
        pos = find_matching_angle_block("<" + joined, 1)
        if pos == -1:
            return [], 0

        body = ("<" + joined)[1:pos]
        trailing = ("<" + joined)[pos + 1 :].strip()
        extra_endif = len(trailing) if trailing and re.fullmatch(r">+", trailing) else 0

        cond = "1" if pass_num == "1" else "0"
        out = [f"#if {cond}"]
        body_lines = body.splitlines()
        j = 0
        while j < len(body_lines):
            line_j = body_lines[j]
            if re.match(r"^\s*DEFINE\b", line_j, flags=re.IGNORECASE):
                nested, consumed = self._consume_define_block(body_lines, j)
                if consumed > 0:
                    out.extend(nested)
                    j += consumed
                    continue
            if re.match(r"^\s*(IFE|IFN|IF)\b", line_j, flags=re.IGNORECASE):
                nested, consumed = self._consume_if_block(body_lines, j)
                if consumed > 0:
                    out.extend(nested)
                    j += consumed
                    continue
            out.extend(self._translate_line(line_j))
            j += 1

        out.append("#endif")
        out.extend(["#endif"] * extra_endif)
        return out, idx - start

    def _consume_if_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        code0, _comment0 = split_comment(lines[start])
        first = code0.strip()
        m = re.match(r"^(IFE|IFN|IF)\s+(.+?),\s*<(.*)$", first, re.IGNORECASE)
        if not m:
            return [], 0

        kind = m.group(1)
        expr = m.group(2)
        after_lt = m.group(3)

        collected = [after_lt]
        idx = start + 1
        balance = 1 + after_lt.count("<") - after_lt.count(">")

        while idx < len(lines) and balance > 0:
            code_i, _ = split_comment(lines[idx])
            piece = code_i.rstrip()
            collected.append(piece)
            balance += piece.count("<") - piece.count(">")
            idx += 1

        joined = "\n".join(collected)
        pos = find_matching_angle_block("<" + joined, 1)
        if pos == -1:
            return [], 0

        body = ("<" + joined)[1:pos]
        trailing = ("<" + joined)[pos + 1 :].strip()
        extra_endif = len(trailing) if trailing and re.fullmatch(r">+", trailing) else 0

        out = [f"#if {self._if_expr(kind, expr)}"]
        body_lines = body.splitlines()
        j = 0
        while j < len(body_lines):
            line_j = body_lines[j]
            if re.match(r"^\s*DEFINE\b", line_j, flags=re.IGNORECASE):
                nested, consumed = self._consume_define_block(body_lines, j)
                if consumed > 0:
                    out.extend(nested)
                    j += consumed
                    continue
            if re.match(r"^\s*(IFE|IFN|IF)\b", line_j, flags=re.IGNORECASE):
                nested, consumed = self._consume_if_block(body_lines, j)
                if consumed > 0:
                    out.extend(nested)
                    j += consumed
                    continue
            if re.match(r"^\s*IF[12]\s*,\s*<", line_j, flags=re.IGNORECASE):
                nested, consumed = self._consume_pass_if_block(body_lines, j)
                if consumed > 0:
                    out.extend(nested)
                    j += consumed
                    continue
            out.extend(self._translate_line(line_j))
            j += 1
        out.append("#endif")
        out.extend(["#endif"] * extra_endif)
        return out, idx - start

    def _if_expr(self, kind: str, expr: str) -> str:
        expr = self._normalize_expr(expr.strip())
        if kind.upper() == "IFE":
            return f"{expr} == 0"
        if kind.upper() == "IFN":
            return f"{expr} != 0"
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

    def _looks_like_alias_expr(self, text: str) -> bool:
        return re.fullmatch(r"[0-9A-Za-z_.$%#@\^<>()+\-*/&!]+", text) is not None

    def _translate_line(self, line: str) -> list[str]:
        code, comment = split_comment(line)
        raw = code.rstrip()
        stripped = raw.strip()

        if stripped == "":
            return [comment if comment else ""]

        if re.fullmatch(r">+", stripped):
            return ["#endif" for _ in stripped]

        stripped, trailing_endif_count = self._split_trailing_endif_closers(stripped)

        m_inline_if = re.match(r"^(IFE|IFN|IF)\s+(.+?),\s*<(.*)>\s*$", stripped, re.IGNORECASE)
        if m_inline_if:
            kind, expr, body = m_inline_if.groups()
            out = [f"#if {self._if_expr(kind, expr)}"]
            out.extend(self._translate_line(body))
            out.append("#endif")
            out.extend(["#endif"] * trailing_endif_count)
            return out

        m_open_if = re.match(r"^(IFE|IFN|IF)\s+(.+?),\s*<\s*$", stripped, re.IGNORECASE)
        if m_open_if:
            kind, expr = m_open_if.groups()
            out = [f"#if {self._if_expr(kind, expr)}"]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        label_match = re.match(r"^([A-Za-z_.$%#@][\w.$%#@]*)(::?)\s*(.*)$", stripped)
        if label_match:
            label, _dbl, rest = label_match.groups()
            mapped = self.map_symbol(label)
            if rest:
                if self._looks_like_alias_expr(rest):
                    out = [f"#define {mapped} {self._normalize_expr(rest)}" + (f" {comment}" if comment else "")]
                    out.extend(["#endif"] * trailing_endif_count)
                    return out
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
            out = [f"#define {self.map_symbol(sym)} {self._normalize_expr(expr.strip())}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        parts = stripped.split(None, 1)
        op = parts[0].upper()
        operand = parts[1].strip() if len(parts) > 1 else ""

        if op == "ORG":
            out = [f"* = {self._normalize_expr(operand)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op == "SEARCH":
            if self.preserve_includes and operand:
                include_name = operand.strip("<>").strip()
                out = [f'.include "{include_name}"' + (f" {comment}" if comment else "")]
                out.extend(["#endif"] * trailing_endif_count)
                return out
            self.warnings.append(f"SEARCH directive left as comment: {stripped}")
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op in {"TITLE", "SUBTTL", "SALL", "PAGE", "RADIX", "PRINTX", "IF1"}:
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op == "END":
            out = [f"; END {operand}".rstrip() + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op == "EXP":
            out = [f".byt {self._normalize_expr(operand)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op in {"IRPC", "IFDIF"}:
            self.warnings.append(f"Directive requires manual review: {stripped}")
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op == "XWD":
            out = [f".word {self._normalize_expr(operand)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op == "BLOCK":
            out = [f".dsb {self._normalize_expr(operand)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        m_dci = re.match(r"^DCI\s*\"(.*)\"$", stripped, re.IGNORECASE)
        if m_dci:
            chars = m_dci.group(1)
            if not chars:
                out = [".byte 0"]
                out.extend(["#endif"] * trailing_endif_count)
                return out
            encoded = [f"'{c}'" for c in chars[:-1]]
            encoded.append(f"'{chars[-1]}'|$80")
            out = [f".byt {', '.join(encoded)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op in IMM_MNEMONICS:
            out = [f"{IMM_MNEMONICS[op]} #{self._normalize_expr(operand)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op in INY_MNEMONICS:
            out = [f"{INY_MNEMONICS[op]} ({self._normalize_expr(operand)}),Y" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op == "JMPD":
            out = [f"JMP ({self._normalize_expr(operand)})" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        m_adr = re.match(r"^ADR\((.+)\)$", stripped, re.IGNORECASE)
        if m_adr:
            out = [f".word {self._normalize_expr(m_adr.group(1).strip())}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if self._looks_like_data_expr(stripped):
            out = [f".byt {self._normalize_expr(stripped)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if len(parts) > 1:
            out = [f"{parts[0]} {self._normalize_expr(parts[1].strip())}" + (f" {comment}" if comment else "")]
        else:
            out = [stripped + (f" {comment}" if comment else "")]
        out.extend(["#endif"] * trailing_endif_count)
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
        out_path = Path(args.out_file) if args.out_file else src_path.with_suffix(".xa65.asm")
        out_path.write_text(result.text, encoding="utf-8")
        print(f"Wrote {out_path}")

    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    if args.strict and result.warnings:
        print("error: strict mode failed due to translation warnings", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
