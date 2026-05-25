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

_OPCODES = {
    "LDA", "LDX", "LDY", "STA", "STX", "STY", "ADC", "SBC", "AND", "ORA", "EOR",
    "CMP", "CPX", "CPY", "INC", "DEC", "INX", "INY", "DEX", "DEY",
    "ASL", "LSR", "ROL", "ROR", "TAX", "TAY", "TXA", "TYA", "TSX", "TXS",
    "PHA", "PLA", "PHP", "PLP", "JMP", "JSR", "RTS", "RTI",
    "BCC", "BCS", "BEQ", "BNE", "BPL", "BMI", "BVC", "BVS",
    "BIT", "NOP", "SED", "CLD", "SEI", "CLI", "SEC", "CLC", "CLV",
    "BRK",
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


class _Unresolved(Exception):
    """Raised by `_try_eval_int` when an unknown identifier is encountered."""


class Translator:
    def __init__(self, symbol_map: dict[str, str] | None = None, preserve_includes: bool = False):
        self.symbol_map = symbol_map or {}
        self.preserve_includes = preserve_includes
        self.warnings: list[str] = []
        self._mapped_symbol_owner: dict[str, str] = {}
        self._emitted_collision_keys: set[tuple[str, str, str]] = set()
        self._macros: dict[str, tuple[list[str], list[str]]] = {}  # name -> (params, body_lines)
        # Current source radix for bare numeric literals (set by `RADIX N`).
        self._radix: int = 10
        # Python-side state for MACRO-10 assembler variables (e.g. `Q=Q+2`).
        # Lets stateful counters such as the `DCE`/`DCI` error-code mechanism
        # be evaluated during translation instead of relying on xa65's
        # `#define` (which cannot represent recursive redefinitions).
        self._vars: dict[str, int] = {}
        # Labels discovered during the pre-pass; used to suppress `=`
        # aliases that would shadow a later `LABEL:` definition.
        self._labels: set[str] = set()
        # Textual `#define X Y` aliases collected during the pre-pass so they
        # can be emitted at the top of the output to satisfy forward refs.
        self._aliases: dict[str, str] = {}

    def _sanitize_symbol(self, symbol: str) -> str:
        # MACRO-10 symbols are case-insensitive but xa65 is case-sensitive.
        # Canonicalize to upper case so mixed-case references (e.g. `ife
        # addprc,<...>` against `ADDPRC==1`) resolve to the same symbol.
        mapped = re.sub(r"[^A-Za-z0-9_]", "_", symbol).upper()
        if not mapped:
            return "_"
        if not re.match(r"^[A-Za-z_]", mapped):
            mapped = f"_{mapped}"
        # MACRO-10 truncates symbols to 6 significant characters; references
        # such as `RESTORE` and `RESTOR` denote the same symbol.
        if len(mapped) > 6:
            mapped = mapped[:6]
        return mapped

    def _normalize_expr(self, expr: str) -> str:
        # MACRO-10 uses `!` as bitwise OR; xa65/C use `|`.
        out_expr = expr.replace("!", "|")
        # Convert explicit-radix prefixes first, marking their digits with a
        # NUL sentinel so the RADIX-state pass below does not re-interpret
        # them. The sentinel is stripped at the end.
        out = _RADIX_OCT_RE.sub(lambda m: f"\x00{int(m.group(1), 8)}", out_expr)
        out = _RADIX_HEX_RE.sub(lambda m: f"\x00{int(m.group(1), 16)}", out)
        out = _RADIX_DEC_RE.sub(lambda m: f"\x00{m.group(1)}", out)
        if self._radix == 8:
            out = re.sub(
                r"(?<![\w$\x00.])([0-7]+)(?!\w)",
                lambda m: str(int(m.group(1), 8)),
                out,
            )
        out = out.replace("\x00", "")
        # Translate MACRO-10 `.` (current PC) to xa65 `*`. Match a bare dot not
        # adjacent to identifier characters.
        out = re.sub(r"(?<![\w.])\.(?![\w.])", "*", out)
        out = _SYMBOL_TOKEN_RE.sub(lambda m: self.map_symbol(m.group(0)), out)
        out = out.replace("<", "").replace(">", "")
        out = self._force_left_assoc(out)
        return out

    @staticmethod
    def _force_left_assoc(expr: str) -> str:
        """Reparenthesize a flat operator expression to be left-associative.

        MACRO-10 evaluates left-to-right with no operator precedence, while
        xa65/C apply standard precedence. We only rewrite when the expression
        is entirely flat (no existing parens) and contains 2+ binary operators,
        which is when ambiguity actually matters (e.g. `BUF-1/256`).
        """
        s = expr.strip()
        if not s or "(" in s or ")" in s or "," in s:
            return expr
        op_chars = set("+-*/&|")
        tokens: list[str] = []
        i = 0
        while i < len(s):
            c = s[i]
            if c.isspace():
                i += 1
                continue
            if c in op_chars and tokens and tokens[-1] not in op_chars:
                tokens.append(c)
                i += 1
                continue
            j = i
            while j < len(s):
                ch = s[j]
                if ch.isspace():
                    break
                if ch in op_chars and j > i and s[j - 1] not in op_chars:
                    break
                j += 1
            tokens.append(s[i:j])
            i = j
        if len(tokens) < 5 or len(tokens) % 2 == 0:
            return expr
        # Skip when all operators share the same C precedence — standard
        # left-to-right grouping already matches MACRO-10 semantics. This also
        # avoids gratuitous leading parens that xa65 would mis-parse as
        # indirect addressing (e.g. `STY (BUF-1)+1`).
        def prec(op: str) -> int:
            if op in "*/%":
                return 1
            if op in "+-":
                return 2
            return 3
        precs = {prec(tokens[k]) for k in range(1, len(tokens), 2)}
        if len(precs) == 1:
            return expr
        acc = tokens[0]
        k = 1
        while k < len(tokens):
            # Skip wrapping the outermost result: leading `(...)` makes xa65
            # interpret operands like `STY (addr)+1` as indirect addressing.
            if k + 2 < len(tokens):
                acc = f"({acc}{tokens[k]}{tokens[k + 1]})"
            else:
                acc = f"{acc}{tokens[k]}{tokens[k + 1]}"
            k += 2
        return acc

    def _try_eval_int(self, expr: str) -> int | None:
        """Attempt to evaluate `expr` to an int using current var/radix state.

        Returns None if the expression references unknown symbols or contains
        unsupported syntax.
        """
        e = expr.strip()
        if not e:
            return None
        # Strip MACRO-10 angle brackets used for grouping.
        e = e.replace("<", "(").replace(">", ")")
        # Convert explicit-radix prefixes, marking digits so the radix pass
        # below does not re-interpret them.
        e = re.sub(r"\^O([0-7]+)", lambda m: f"\x00{int(m.group(1), 8)}", e)
        e = re.sub(r"\^X([0-9A-Fa-f]+)", lambda m: f"\x00{int(m.group(1), 16)}", e)
        e = re.sub(r"\^D(\d+)", lambda m: f"\x00{m.group(1)}", e)
        if self._radix == 8:
            e = re.sub(
                r"(?<![\w$\x00.])([0-7]+)(?!\w)",
                lambda m: str(int(m.group(1), 8)),
                e,
            )
        e = e.replace("\x00", "")
        # MACRO-10 `&` is bitwise AND; Python uses `&` already. `!` is OR in
        # some MACRO-10 dialects but BASIC-M6502 uses `|` consistently, so no
        # mapping needed here.
        # Substitute known identifiers; bail on unknowns.
        def sub_id(m: re.Match[str]) -> str:
            tok = m.group(0)
            if tok in self._vars:
                return str(self._vars[tok])
            mapped = self.symbol_map.get(tok)
            if mapped and mapped in self._vars:
                return str(self._vars[mapped])
            raise _Unresolved(tok)
        try:
            e = re.sub(r"[A-Za-z_.][\w.]*", sub_id, e)
        except _Unresolved:
            return None
        # Now expression should be pure arithmetic over ints.
        if not re.match(r"^[\d\s+\-*/%()&|^]+$", e):
            return None
        try:
            return int(eval(e, {"__builtins__": {}}, {}))
        except Exception:
            return None

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
        # Pre-pass: discover numeric constants and textual aliases so forward
        # references resolve in the real emit pass.
        forward_vars: dict[str, int] = {}
        forward_aliases: dict[str, str] = {}
        if not getattr(self, "_in_prepass", False):
            self._in_prepass = True
            try:
                self._translate_pass(source)
                forward_vars = dict(self._vars)
                forward_aliases = dict(self._aliases)
            finally:
                self._in_prepass = False
            # Reset mutating state for the real emit pass; seed with discovered
            # values so forward `==` constants substitute correctly.
            self.warnings = []
            self._mapped_symbol_owner = {}
            self._emitted_collision_keys = set()
            self._macros = {}
            self._radix = 10
            self._vars = dict(forward_vars)
            self._aliases = {}
        return self._translate_pass(
            source, forward_vars=forward_vars, forward_aliases=forward_aliases
        )

    def _translate_pass(
        self,
        source: str,
        forward_vars: dict[str, int] | None = None,
        forward_aliases: dict[str, str] | None = None,
    ) -> TranslationResult:
        lines = source.splitlines()
        out: list[str] = []
        idx = 0
        comment_block_delim: str | None = None
        if forward_vars:
            for name, value in forward_vars.items():
                if name.isidentifier():
                    out.append(f"#define {name} {value}")
        if forward_aliases:
            for name, body in forward_aliases.items():
                if name.isidentifier() and name not in (forward_vars or {}):
                    out.append(f"#define {name} {body}")

        while idx < len(lines):
            line = lines[idx]
            stripped = split_comment(line)[0].strip()

            if comment_block_delim:
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
                if consumed > 0:
                    out.extend(block)
                    idx += consumed
                    continue

            if re.match(r"^\s*(IFE|IFN|IF|IFDEF|IFNDEF)\b", line, flags=re.IGNORECASE):
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

            # Handle REPEAT
            m_repeat = re.match(r"^\s*REPEAT\s+([^,]+),?\s*(.*)$", line, re.IGNORECASE)
            if m_repeat:
                n_times_str, rest = m_repeat.groups()
                body_lines = []
                consumed = 0
                if '<' in rest:
                    collected, consumed = self._consume_raw_bracketed_block(lines, idx)
                    joined = "\n".join(collected)
                    first_lt = joined.find("<")
                    last_gt = joined.rfind(">")
                    if first_lt != -1 and last_gt != -1:
                        inner = joined[first_lt+1:last_gt]
                        body_lines = inner.splitlines()
                elif rest.strip():
                    body_lines = [rest.strip()]
                    consumed = 1
                
                if body_lines:
                    try:
                        val_str = n_times_str.strip()
                        # Very crude evaluation for things like 3+ADDPRC
                        if '+' in val_str:
                            parts_plus = val_str.split('+')
                            val = 0
                            for p in parts_plus:
                                p = p.strip()
                                if p.isdigit(): val += int(p)
                                elif p.startswith('^O'): val += int(p[2:], 8)
                                elif p.startswith('$'): val += int(p[1:], 16)
                                else: 
                                    raise ValueError("Complex expression")
                        elif val_str.startswith('^O'): val = int(val_str[2:], 8)
                        elif val_str.startswith('$'): val = int(val_str[1:], 16)
                        else: val = int(val_str)
                        
                        for _ in range(val):
                            for bline in body_lines:
                                out.extend(self._translate_line(bline))
                    except (ValueError, TypeError):
                        out.append(f"; REPEAT {n_times_str} ignored")
                    
                    idx += consumed
                    continue

            out.extend(self._translate_line(line))
            idx += 1

        return TranslationResult(text="\n".join(out) + "\n", warnings=self.warnings)

    def _consume_raw_bracketed_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        collected: list[str] = []
        idx = start
        balance = 0
        started = False
        while idx < len(lines):
            ln = lines[idx]
            collected.append(ln)
            delta = angle_delta(ln)
            code, _ = split_comment(ln)
            if "<" in code:
                started = True
            balance += delta
            idx += 1
            if started and balance <= 0:
                break
        return collected, idx - start

    def _consume_define_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        collected, consumed = self._consume_raw_bracketed_block(lines, start)
        joined = "\n".join(collected)
        m = re.search(r"DEFINE\s+", joined, flags=re.IGNORECASE)
        if not m:
            self.warnings.append("Unparsed DEFINE block; preserved as comments.")
            return ([f"; {line}" for line in collected], consumed)

        header_start = m.start()
        first_lt = joined.find("<", header_start)
        if first_lt == -1:
            self.warnings.append("DEFINE without body; preserved as comments.")
            return ([f"; {line}" for line in collected], consumed)

        header = joined[header_start:first_lt].strip()
        body_end = joined.rfind(">")
        if body_end == -1 or body_end <= first_lt:
            self.warnings.append("Unbalanced DEFINE body; preserved as comments.")
            return ([f"; {line}" for line in collected], consumed)

        body = joined[first_lt + 1 : body_end]
        header_match = re.match(
            r"^DEFINE\s+([A-Za-z_.$%#@][\w.$%#@]*)\s*(?:\(([^)]*)\))?",
            header,
            flags=re.IGNORECASE,
        )
        if not header_match:
            self.warnings.append(f"Could not parse DEFINE header: {header}")
            return ([f"; {line}" for line in collected], consumed)

        name = self.map_symbol(header_match.group(1).strip()).upper()
        params_raw = (header_match.group(2) or "").strip()
        params = [self.map_symbol(p.strip()) for p in params_raw.split(",") if p.strip()]

        # MACRO-10 lets a DEFINE shadow a built-in opcode under a guard like
        # `IFE RORSW,<DEFINE ROR (WD),<...>>`, with the opposite branch using
        # the real opcode. We can't track that conditional, so we never let a
        # DEFINE shadow an actual 6502 opcode and rely on xa65's native one.
        if name in _OPCODES:
            return [f"; DEFINE {name} (shadowed; using opcode)"], consumed

        self._macros[name] = (params, body.splitlines())
        return [f"; DEFINE {name}"], consumed


    def _if_directive(self, kind: str, expr: str) -> str:
        """Return the xa65 conditional directive line for a MACRO-10 IF*."""
        norm = self._normalize_expr(expr.strip())
        ku = kind.upper()
        if ku == "IFE":
            return f"#if {norm} == 0"
        if ku == "IFN":
            return f"#if {norm} != 0"
        if ku == "IFDEF":
            return f"#ifdef {norm}"
        if ku == "IFNDEF":
            return f"#ifndef {norm}"
        return f"#if {norm}"

    def _if_expr(self, kind: str, expr: str) -> str:
        expr = self._normalize_expr(expr.strip())
        if kind.upper() == "IFE":
            return f"{expr} == 0"
        if kind.upper() == "IFN":
            return f"{expr} != 0"
        if kind.upper() == "IFDEF":
            return f"defined({expr})"
        if kind.upper() == "IFNDEF":
            return f"!defined({expr})"
        return expr

    def _consume_if_block(self, lines: list[str], start: int) -> tuple[list[str], int]:
        code0, _comment0 = split_comment(lines[start])
        first = code0.strip()
        m = re.match(r"^(IFE|IFN|IF|IFDEF|IFNDEF)\s+(.+?),\s*<(.*)$", first, re.IGNORECASE)
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

        out = [self._if_directive(kind, expr)]
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
            if re.match(r"^\s*(IFE|IFN|IF|IFDEF|IFNDEF)\b", line_j, flags=re.IGNORECASE):
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
            if re.match(r"^\s*(IFE|IFN|IF|IFDEF|IFNDEF)\b", line_j, flags=re.IGNORECASE):
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
        if kind.upper() == "IFDEF":
            return f"defined({expr})"
        if kind.upper() == "IFNDEF":
            return f"!defined({expr})"
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

        m_inline_repeat = re.match(r"^REPEAT\s+([^,]+),\s*<(.*)>\s*$", stripped, re.IGNORECASE)
        if m_inline_repeat:
            count_str, body = m_inline_repeat.groups()
            count = self._try_eval_int(count_str.strip())
            if count is not None:
                out: list[str] = []
                if comment:
                    out.append(comment)
                for _ in range(count):
                    out.extend(self._translate_line(body))
                out.extend(["#endif"] * trailing_endif_count)
                return out

        m_inline_if = re.match(r"^(IFE|IFN|IF|IFDEF|IFNDEF)\s+(.+?),\s*<(.*)>\s*$", stripped, re.IGNORECASE)
        if m_inline_if:
            kind, expr, body = m_inline_if.groups()
            out = [self._if_directive(kind, expr)]
            out.extend(self._translate_line(body))
            out.append("#endif")
            out.extend(["#endif"] * trailing_endif_count)
            return out

        m_open_if = re.match(r"^(IFE|IFN|IF|IFDEF|IFNDEF)\s+(.+?),\s*<\s*$", stripped, re.IGNORECASE)
        if m_open_if:
            kind, expr = m_open_if.groups()
            out = [self._if_directive(kind, expr)]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        label_match = re.match(r"^([A-Za-z_.$%#@][\w.$%#@]*)(::?)!?\s*(.*)$", stripped)
        if label_match:
            label, _dbl, rest = label_match.groups()
            mapped = self.map_symbol(label)
            self._labels.add(mapped)
            if rest:
                rest_out = self._translate_line(rest)
                if not rest_out:
                    return [f"{mapped}:" + (f" {comment}" if comment else "")]
                first = rest_out[0]
                # Preprocessor directives cannot share a line with a label.
                if first.startswith("#"):
                    out = [f"{mapped}:" + (f" {comment}" if comment else "")] + rest_out
                elif (re.fullmatch(r"[A-Za-z_.$%#@][\w.$%#@]*", first.strip()) and 
                      first.strip().upper() not in _OPCODES and 
                      first.strip().upper() not in IMM_MNEMONICS and 
                      first.strip().upper() not in INY_MNEMONICS and
                      first.strip().upper() not in self._macros):
                    # Bare symbol after label colon is a data byte, e.g. LINWID: LINLEN
                    rest_out[0] = f"{mapped}: .byt {first}".rstrip()
                    if comment:
                        rest_out[0] += f" {comment}"
                    out = rest_out
                else:
                    rest_out[0] = f"{mapped}: {first}".rstrip()
                    if comment:
                        rest_out[0] += f" {comment}"
                    out = rest_out
                out.extend(["#endif"] * trailing_endif_count)
                return out
            return [f"{mapped}:" + (f" {comment}" if comment else "")]

        assign = re.match(r"^([A-Za-z_.$%#@][\w.$%#@]*)\s*(==|=)\s*(.+)$", stripped)
        if assign:
            sym, eq, expr = assign.groups()
            mapped_sym = self.map_symbol(sym)
            value = self._try_eval_int(expr.strip())
            if value is not None:
                self._vars[sym] = value
                self._vars[mapped_sym] = value
                # Emit `#define` for both `=` and `==` so xa65 sees the
                # numeric value. The `=` form is technically redefinable in
                # MACRO-10, but xa65 tolerates `#define` redefinition and we
                # already track the live value in `self._vars` for use by
                # subsequent `==Q` snapshots.
                out = []
                if comment:
                    out.append(comment)
                out.append(f"#define {mapped_sym} {value}")
                out.extend(["#endif"] * trailing_endif_count)
                return out
            # Fallback: emit textual #define. Comment goes on its own line so
            # it does not leak into the macro body.
            out = []
            if comment:
                out.append(comment)
            alias_body = self._normalize_expr(expr.strip())
            self._aliases[mapped_sym] = alias_body
            out.append(f"#define {mapped_sym} {alias_body}")
            out.extend(["#endif"] * trailing_endif_count)
            return out

        parts = stripped.split(None, 1)
        op = parts[0].upper()
        operand = parts[1].strip() if len(parts) > 1 else ""
        # MACRO-10 allows macro calls without whitespace before the argument,
        # e.g. `DCE"NF"` or `DCI(A)`. Split on first non-identifier char and
        # check if the prefix is a known macro.
        m_nospace = re.match(r"^([A-Za-z_][\w.]*)([^\w.].*)$", parts[0])
        if m_nospace:
            candidate = m_nospace.group(1).upper()
            if candidate in self._macros:
                op = candidate
                tail = m_nospace.group(2)
                operand = (tail + (" " + operand if operand else "")).strip()

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

        if op == "RADIX":
            try:
                self._radix = int(operand.strip(), 10)
            except ValueError:
                self.warnings.append(f"Could not parse RADIX operand: {operand!r}")
            out = [f"; {stripped}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op in {"TITLE", "SUBTTL", "SALL", "PAGE", "IF1", "LIST", "NLIST", "XLIST", "NOLIST"} or op.startswith("PRINTX") or op.startswith("."):
            # `.XCREF`, `.CREF`, `.LIST`, `.NLIST`, etc. are listing-only
            # pseudo-ops with no machine-code effect; preserve as comments.
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

        m_dt = re.match(r'^DT\s*"(.*)"$', stripped, re.IGNORECASE)
        if m_dt:
            out = [f'.asc "{m_dt.group(1)}"' + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        # `DC "STRING"` (or `DC("STRING")`): emit ASCII bytes with the last
        # byte's high bit set (BASIC-M6502 end-of-string marker).
        m_dc = re.match(r'^DC\s*\(?\s*"([^"]*)"\s*\)?$', stripped, re.IGNORECASE)
        if m_dc:
            s = m_dc.group(1)
            if s:
                def char_lit(c: str) -> str:
                    return f"'{c}'" if c != "'" else "39"
                if len(s) == 1:
                    body = f"{char_lit(s)}|$80"
                else:
                    prefix = ", ".join(char_lit(c) for c in s[:-1])
                    body = f"{prefix}, {char_lit(s[-1])}|$80"
                out = [f".byt {body}" + (f" {comment}" if comment else "")]
            else:
                out = [f"; DC (empty)" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        m_adr = re.match(r"^ADR\s*\((.+)\)$", stripped, re.IGNORECASE)
        if m_adr:
            out = [f".word {self._normalize_expr(m_adr.group(1).strip())}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if self._looks_like_data_expr(stripped):
            out = [f".byt {self._normalize_expr(stripped)}" + (f" {comment}" if comment else "")]
            out.extend(["#endif"] * trailing_endif_count)
            return out

        if op in self._macros:
            params, body_lines = self._macros[op]
            # Split operand by comma for multi-param macros
            args = [a.strip() for a in operand.split(',')] if operand else []
            # Expansion
            expanded_out = []
            for bline in body_lines:
                # Replace params in bline
                for i, pname in enumerate(params):
                    val = args[i] if i < len(args) else ""
                    # Match parameter as whole word
                    bline = re.sub(r'\b' + re.escape(pname) + r'\b', val, bline)
                expanded_out.extend(self._translate_line(bline))
            
            if comment:
                if expanded_out: expanded_out[0] += f" {comment}"
                else: expanded_out = [comment]
            
            expanded_out.extend(["#endif"] * trailing_endif_count)
            return expanded_out

        if len(parts) > 1:
            operand_norm = self._normalize_expr(parts[1].strip())
            # xa65 expresses accumulator addressing as the bare opcode (e.g.
            # `ASL` rather than `ASL A`). Strip a literal `A` (or `A,`) operand
            # for the shift/rotate/inc/dec family.
            if op in {"ASL", "LSR", "ROL", "ROR", "INC", "DEC"} and operand_norm.rstrip(",").strip().upper() == "A":
                out = [parts[0] + (f" {comment}" if comment else "")]
            else:
                out = [f"{parts[0]} {operand_norm}" + (f" {comment}" if comment else "")]
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
