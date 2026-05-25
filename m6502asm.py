#!/usr/bin/env python3
"""
m6502asm.py — MACRO-10 / M6502 cross-assembler

Assembles Microsoft BASIC for 6502 (m6502.asm) and similar source
files that use DEC MACRO-10 syntax with the M6502 macro library.

M6502.MAC addressing-mode conventions (built-in):
  INSTR            implied (no operand): BRK, CLC, INX, NOP, RTS, …
  INSTR A[,]       accumulator:  ASL A,  /  ASL A  (for shift/rotate)
  INSTR addr       zero-page (0–255) or absolute (256–65535), auto-select
  INSTR addr,X     zero-page,X or absolute,X
  INSTR addr,Y     absolute,Y  (zero-page,Y for STX / LDX)
  INSTRI  val      immediate  (#val)   — e.g. LDAI, CMPI, ADCI, …
  INSTRDY addr     (addr),Y   indirect-indexed Y  — e.g. LDADY, STADY
  JMPD    addr     JMP (addr)  indirect JMP

Usage:
  python3 m6502asm.py [options] input.asm
  -o FILE         output file  (default: <input>.bin)
  -f bin|ihex     output format (default: bin)
  -D SYM[=VAL]    pre-define symbol (default value 1)
  -v              verbose / show assembly listing
"""

import sys, re, os, struct, argparse
from collections import OrderedDict

# ─────────────────────────────────────────────────────────────────────────────
# 6502 opcode table  { (MNEMONIC, MODE) : opcode_byte }
# Modes: imp acc imm zp zpx zpy abs abx aby ind inx iny rel
# ─────────────────────────────────────────────────────────────────────────────
OPCODES = {
    ('ADC','imm'):0x69,('ADC','zp'):0x65,('ADC','zpx'):0x75,
    ('ADC','abs'):0x6D,('ADC','abx'):0x7D,('ADC','aby'):0x79,
    ('ADC','inx'):0x61,('ADC','iny'):0x71,
    ('AND','imm'):0x29,('AND','zp'):0x25,('AND','zpx'):0x35,
    ('AND','abs'):0x2D,('AND','abx'):0x3D,('AND','aby'):0x39,
    ('AND','inx'):0x21,('AND','iny'):0x31,
    ('ASL','acc'):0x0A,('ASL','zp'):0x06,('ASL','zpx'):0x16,
    ('ASL','abs'):0x0E,('ASL','abx'):0x1E,
    ('BCC','rel'):0x90,('BCS','rel'):0xB0,('BEQ','rel'):0xF0,
    ('BIT','zp'):0x24, ('BIT','abs'):0x2C,
    ('BMI','rel'):0x30,('BNE','rel'):0xD0,('BPL','rel'):0x10,
    ('BRK','imp'):0x00,
    ('BVC','rel'):0x50,('BVS','rel'):0x70,
    ('CLC','imp'):0x18,('CLD','imp'):0xD8,('CLI','imp'):0x58,('CLV','imp'):0xB8,
    ('CMP','imm'):0xC9,('CMP','zp'):0xC5,('CMP','zpx'):0xD5,
    ('CMP','abs'):0xCD,('CMP','abx'):0xDD,('CMP','aby'):0xD9,
    ('CMP','inx'):0xC1,('CMP','iny'):0xD1,
    ('CPX','imm'):0xE0,('CPX','zp'):0xE4,('CPX','abs'):0xEC,
    ('CPY','imm'):0xC0,('CPY','zp'):0xC4,('CPY','abs'):0xCC,
    ('DEC','zp'):0xC6, ('DEC','zpx'):0xD6,('DEC','abs'):0xCE,('DEC','abx'):0xDE,
    ('DEX','imp'):0xCA,('DEY','imp'):0x88,
    ('EOR','imm'):0x49,('EOR','zp'):0x45,('EOR','zpx'):0x55,
    ('EOR','abs'):0x4D,('EOR','abx'):0x5D,('EOR','aby'):0x59,
    ('EOR','inx'):0x41,('EOR','iny'):0x71,   # 0x51 for iny but keep table correct:
    ('INC','zp'):0xE6, ('INC','zpx'):0xF6,('INC','abs'):0xEE,('INC','abx'):0xFE,
    ('INX','imp'):0xE8,('INY','imp'):0xC8,
    ('JMP','abs'):0x4C,('JMP','ind'):0x6C,
    ('JSR','abs'):0x20,
    ('LDA','imm'):0xA9,('LDA','zp'):0xA5,('LDA','zpx'):0xB5,
    ('LDA','abs'):0xAD,('LDA','abx'):0xBD,('LDA','aby'):0xB9,
    ('LDA','inx'):0xA1,('LDA','iny'):0xB1,
    ('LDX','imm'):0xA2,('LDX','zp'):0xA6,('LDX','zpy'):0xB6,
    ('LDX','abs'):0xAE,('LDX','aby'):0xBE,
    ('LDY','imm'):0xA0,('LDY','zp'):0xA4,('LDY','zpx'):0xB4,
    ('LDY','abs'):0xAC,('LDY','abx'):0xBC,
    ('LSR','acc'):0x4A,('LSR','zp'):0x46,('LSR','zpx'):0x56,
    ('LSR','abs'):0x4E,('LSR','abx'):0x5E,
    ('NOP','imp'):0xEA,
    ('ORA','imm'):0x09,('ORA','zp'):0x05,('ORA','zpx'):0x15,
    ('ORA','abs'):0x0D,('ORA','abx'):0x1D,('ORA','aby'):0x19,
    ('ORA','inx'):0x01,('ORA','iny'):0x11,
    ('PHA','imp'):0x48,('PHP','imp'):0x08,
    ('PLA','imp'):0x68,('PLP','imp'):0x28,
    ('ROL','acc'):0x2A,('ROL','zp'):0x26,('ROL','zpx'):0x36,
    ('ROL','abs'):0x2E,('ROL','abx'):0x3E,
    ('ROR','acc'):0x6A,('ROR','zp'):0x66,('ROR','zpx'):0x76,
    ('ROR','abs'):0x6E,('ROR','abx'):0x7E,
    ('RTI','imp'):0x40,('RTS','imp'):0x60,
    ('SBC','imm'):0xE9,('SBC','zp'):0xE5,('SBC','zpx'):0xF5,
    ('SBC','abs'):0xED,('SBC','abx'):0xFD,('SBC','aby'):0xF9,
    ('SBC','inx'):0xE1,('SBC','iny'):0xF1,
    ('SEC','imp'):0x38,('SED','imp'):0xF8,('SEI','imp'):0x78,
    ('STA','zp'):0x85, ('STA','zpx'):0x95,
    ('STA','abs'):0x8D,('STA','abx'):0x9D,('STA','aby'):0x99,
    ('STA','inx'):0x81,('STA','iny'):0x91,
    ('STX','zp'):0x86, ('STX','zpy'):0x96,('STX','abs'):0x8E,
    ('STY','zp'):0x84, ('STY','zpx'):0x94,('STY','abs'):0x8C,
    ('TAX','imp'):0xAA,('TAY','imp'):0xA8,
    ('TSX','imp'):0xBA,
    ('TXA','imp'):0x8A,('TXS','imp'):0x9A,('TYA','imp'):0x98,
}
# fix EOR iny (should be 0x51, not 0x71 which is ADC iny)
OPCODES[('EOR','iny')] = 0x51

BRANCHES    = {'BCC','BCS','BEQ','BMI','BNE','BPL','BVC','BVS'}
IMPLIED     = {'BRK','CLC','CLD','CLI','CLV','DEX','DEY','INX','INY',
               'NOP','PHA','PHP','PLA','PLP','RTI','RTS',
               'SEC','SED','SEI','TAX','TAY','TSX','TXA','TXS','TYA'}
ACC_CAPABLE = {'ASL','LSR','ROL','ROR'}

# M6502.MAC immediate-mode variants: suffix I → immediate
IMM_MNEMONICS = {
    'LDAI':'LDA','LDXI':'LDX','LDYI':'LDY',
    'CMPI':'CMP','CPXI':'CPX','CPYI':'CPY',
    'ADCI':'ADC','SBCI':'SBC',
    'ANDI':'AND','ORAI':'ORA','EORI':'EOR',
    'STAI':'STA',   # rare but possible
}
# suffix DY → (zp),Y  indirect-indexed
INY_MNEMONICS = {
    'LDADY':'LDA','STADY':'STA',
    'ADCDY':'ADC','SBCDY':'SBC','CMPDY':'CMP',
    'ANDDY':'AND','ORADY':'ORA','EORDY':'EOR',
}
# Base mnemonics that know about indexed addressing
BASE_MNEMONICS = frozenset(m for m,_ in OPCODES)

# All 6502 mnemonics (base + variants)
ALL_MNEMONICS = (BASE_MNEMONICS |
                 frozenset(IMM_MNEMONICS) |
                 frozenset(INY_MNEMONICS) |
                 {'JMPD'})


# ─────────────────────────────────────────────────────────────────────────────
# Error handling
# ─────────────────────────────────────────────────────────────────────────────
class AsmError(Exception):
    def __init__(self, msg, lineno=None):
        self.lineno = lineno
        loc = f" (line {lineno})" if lineno else ""
        super().__init__(f"AsmError{loc}: {msg}")


def normalize_symbol(name: str) -> str:
    """Normalize symbol names to MACRO-10 rules for table keys.

    - Uppercase
    - Only the first six characters are significant (truncate)
    """
    if not name:
        return name
    n = name.upper()
    # MACRO-10 uses only the first six significant characters
    return n[:6]


# ─────────────────────────────────────────────────────────────────────────────
# Expression evaluator
# ─────────────────────────────────────────────────────────────────────────────
class ExprEval:
    """
    Evaluate MACRO-10 expressions.
    Operators (left-to-right, no precedence): + - * / & !
    Grouping: <expr>  or  (expr)
    Literals: decimal, ^Onnn (octal), ^Bnnn (binary), "x" (ASCII char)
    Unary: - ^C (bitwise complement)
    Special: . = current PC
    """
    def __init__(self, symbols: dict, pc: int, radix: int = 10,
                 pass_num: int = 1):
        self.symbols = symbols
        self.pc = pc
        self.radix = radix
        self.pass_num = pass_num
        self.had_undef: bool = False  # set if eval saw any undefined symbol

    def eval(self, text: str) -> int:
        """Evaluate expression string; raises AsmError on error."""
        text = text.strip()
        val, pos = self._expr(text, 0)
        return val & 0xFFFF  # 16-bit result

    def _expr(self, text: str, pos: int):
        """Parse and evaluate from pos; return (value, new_pos)."""
        val, pos = self._unary(text, pos)
        while pos < len(text):
            ch = text[pos]
            if ch in ('+', '-', '*', '/', '&', '!'):
                pos += 1
                rhs, pos = self._unary(text, pos)
                if   ch == '+': val += rhs
                elif ch == '-': val -= rhs
                elif ch == '*': val *= rhs
                elif ch == '/':
                    if rhs == 0:
                        raise AsmError("division by zero in expression")
                    val = int(val / rhs)  # integer divide preserving sign
                elif ch == '&': val &= rhs
                elif ch == '!': val |= rhs
            else:
                break
        return val, pos

    def _unary(self, text: str, pos: int):
        pos = self._skip_ws(text, pos)
        if pos >= len(text):
            return 0, pos
        ch = text[pos]
        if ch == '-':
            v, pos = self._unary(text, pos + 1)
            return -v, pos
        if ch == '^' and pos + 1 < len(text):
            nxt = text[pos + 1].upper()
            if nxt == 'O':  # octal
                pos += 2
                pos = self._skip_ws(text, pos)
                end = pos
                while end < len(text) and text[end] in '01234567':
                    end += 1
                return int(text[pos:end] or '0', 8), end
            if nxt == 'D':  # decimal
                pos += 2
                pos = self._skip_ws(text, pos)
                end = pos
                while end < len(text) and text[end].isdigit():
                    end += 1
                return int(text[pos:end] or '0', 10), end
            if nxt == 'B':  # binary
                pos += 2
                pos = self._skip_ws(text, pos)
                end = pos
                while end < len(text) and text[end] in '01':
                    end += 1
                return int(text[pos:end] or '0', 2), end
            if nxt == 'C':  # bitwise complement
                v, pos = self._unary(text, pos + 2)
                return (~v) & 0xFFFF, pos
        if ch == '<' or ch == '(':
            close = '>' if ch == '<' else ')'
            depth = 1
            pos += 1
            start = pos
            while pos < len(text) and depth > 0:
                if text[pos] in '<(':
                    depth += 1
                elif text[pos] in '>)':
                    depth -= 1
                pos += 1
            inner = text[start:pos - 1]
            v, _ = self._expr(inner, 0)
            return v, pos
        if ch == '"':
            # ASCII char literal: "x"  or "xy" (last char used, MACRO-10 radix50)
            pos += 1
            if pos >= len(text):
                return 0, pos
            c = text[pos]
            pos += 1
            if pos < len(text) and text[pos] == '"':
                pos += 1  # closing quote
            return ord(c) & 0x7F, pos
        if ch == '.':
            return self.pc, pos + 1
        # identifier / symbol  (must start with a letter or special char, not digit)
        if ch.isalpha() or ch in '._$%#@':
            end = pos
            while end < len(text) and (text[end].isalnum() or text[end] in '._$%#@'):
                end += 1
            name = text[pos:end]
            key = normalize_symbol(name)
            if key in self.symbols:
                return self.symbols[key], end
            # undefined symbol: return 0 in pass 1, raise in pass 2
            self.had_undef = True
            if self.pass_num == 1:
                return 0, end
            raise AsmError(f"undefined symbol '{name}'")
        # plain decimal (or current radix) — starts with digit
        if ch.isdigit():
            end = pos
            while end < len(text) and text[end].isdigit():
                end += 1
            numstr = text[pos:end]
            try:
                return int(numstr, self.radix), end
            except ValueError:
                return int(numstr, 10), end  # fallback: treat as decimal
        return 0, pos

    @staticmethod
    def _skip_ws(text, pos):
        while pos < len(text) and text[pos] in ' \t':
            pos += 1
        return pos


# ─────────────────────────────────────────────────────────────────────────────
# Source scanner (angle-bracket aware)
# ─────────────────────────────────────────────────────────────────────────────
def read_angle_block(text: str, pos: int) -> tuple:
    """
    Parse a balanced <...> block starting at pos (pos must be '<').
    Returns (inner_content, new_pos_after_'>').
    """
    assert text[pos] == '<', f"expected '<' at pos {pos}, got {text[pos]!r}"
    depth = 1
    pos += 1
    start = pos
    while pos < len(text) and depth > 0:
        c = text[pos]
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        pos += 1
    return text[start:pos - 1], pos


def skip_ws(text: str, pos: int) -> int:
    """Skip spaces, tabs and form-feeds."""
    while pos < len(text) and text[pos] in ' \t\f':
        pos += 1
    return pos


def skip_ws_nl(text: str, pos: int) -> int:
    """Skip whitespace including newlines and form-feeds.

    Form-feed (``\\f``, 0x0C) is treated as whitespace because real DEC
    sources use it as a page-break marker (see m6502.asm just before
    SUBTTL lines).  Without this the form-feed would otherwise be parsed
    as the start of a bare expression and silently emit a 0 byte in pass 1
    only — producing a one-byte drift between passes and corrupting all
    forward symbol values from that line onward.
    """
    while pos < len(text) and text[pos] in ' \t\r\n\f':
        pos += 1
    return pos


def read_token(text: str, pos: int) -> tuple:
    """
    Read a MACRO-10 identifier / number / string token.
    Returns (token_str, new_pos).  token_str='' means nothing found.
    """
    pos = skip_ws(text, pos)
    if pos >= len(text) or text[pos] == ';':
        return '', pos
    ch = text[pos]
    # String literal
    if ch == '"':
        end = pos + 1
        # find closing quote (allow escaped "")
        while end < len(text) and text[end] != '"':
            end += 1
        if end < len(text):
            end += 1
        return text[pos:end], end
    # Number / octal / binary
    if ch == '^':
        end = pos + 2
        while end < len(text) and (text[end].isalnum()):
            end += 1
        return text[pos:end], end
    # Angle-bracketed group
    if ch == '<':
        inner, npos = read_angle_block(text, pos)
        return '<' + inner + '>', npos
    # Identifier (includes $, %, #, @, .)
    if ch.isalpha() or ch in '._$%#@':
        end = pos
        while end < len(text) and (text[end].isalnum() or text[end] in '._$%#@'):
            end += 1
        return text[pos:end], end
    # Decimal number
    if ch.isdigit():
        end = pos
        while end < len(text) and text[end].isdigit():
            end += 1
        return text[pos:end], end
    # Single special char
    return ch, pos + 1


def split_args(text: str) -> list:
    """
    Split MACRO-10 argument list by commas, respecting <...> depth.
    Returns list of stripped arg strings.
    """
    args = []
    depth = 0
    current = []
    i = 0
    while i < len(text):
        c = text[i]
        if c == '<':
            depth += 1
        elif c == '>':
            depth -= 1
        elif c == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    args.append(''.join(current).strip())
    return args


# ─────────────────────────────────────────────────────────────────────────────
# Output emitter
# ─────────────────────────────────────────────────────────────────────────────
class Emitter:
    """Collects (address, byte) pairs and produces binary output."""
    def __init__(self):
        self.segments = []   # list of (start_addr, bytearray)
        self._cur_addr = None
        self._cur_buf = None
        # optional listing buffer populated during pass 2 when verbose
        self.listing = []  # list of (addr, byte)

    def set_origin(self, addr: int):
        if self._cur_buf is not None and len(self._cur_buf) > 0:
            self.segments.append((self._cur_addr, bytes(self._cur_buf)))
        self._cur_addr = addr
        self._cur_buf = bytearray()

    def reserve(self, n: int):
        """Reserve ``n`` bytes (e.g. for BLOCK).  Closes the current
        segment so the binary emitter doesn't actually store the zeros,
        and starts the next emit at ``current_addr + n``.  No entries are
        added to ``self.listing`` (so the assembly listing won't show a
        long run of ``00`` bytes for large BLOCK directives).  The to_binary
        helper still zero-fills the gap when producing a flat binary, so
        output is identical to emitting zero bytes."""
        if n <= 0:
            return
        cur_end = (self._cur_addr or 0) + (len(self._cur_buf or b''))
        # close current segment
        if self._cur_buf is not None and len(self._cur_buf) > 0:
            self.segments.append((self._cur_addr, bytes(self._cur_buf)))
        self._cur_addr = cur_end + n
        self._cur_buf = bytearray()

    def emit(self, byte: int):
        if self._cur_buf is None:
            self._cur_addr = 0
            self._cur_buf = bytearray()
        self._cur_buf.append(byte & 0xFF)
        # record for listing
        try:
            self.listing.append((self._cur_addr + len(self._cur_buf) - 1, byte & 0xFF))
        except Exception:
            pass

    def flush(self):
        if self._cur_buf is not None and len(self._cur_buf) > 0:
            self.segments.append((self._cur_addr, bytes(self._cur_buf)))
            self._cur_buf = bytearray()

    def to_binary(self) -> bytes:
        """Produce a flat binary spanning min..max address."""
        self.flush()
        if not self.segments:
            return b''
        lo = min(a for a, _ in self.segments)
        hi = max(a + len(d) for a, d in self.segments)
        buf = bytearray(hi - lo)
        for addr, data in self.segments:
            buf[addr - lo:addr - lo + len(data)] = data
        return bytes(buf)

    def to_ihex(self) -> str:
        """Produce Intel HEX format."""
        self.flush()
        lines = []
        for start, data in self.segments:
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + 16]
                addr = (start + offset) & 0xFFFF
                rec = bytes([len(chunk), (addr >> 8) & 0xFF, addr & 0xFF, 0x00]) + chunk
                csum = (-sum(rec)) & 0xFF
                lines.append(':' + rec.hex().upper() + f'{csum:02X}')
                offset += 16
        lines.append(':00000001FF')
        return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main Assembler
# ─────────────────────────────────────────────────────────────────────────────
class Assembler:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.symbols: dict = {}
        self.predefined: set = set()  # symbols set via -D
        # mapping normalized_key -> set(original symbol names)
        self.symbol_names: dict = {}
        self.macros: dict = {}      # name -> (params_list, body_str)
        self.pc: int = 0
        self.pass_num: int = 1
        self.radix: int = 10
        self.emitter: Emitter = Emitter()
        self._local_ctr: int = 0   # counter for unique local labels
        self._cur_lineno: int = 1  # current source line number (top-level)
        self._nesting: int = 0     # > 0 while inside macro/IF/REPEAT body
        self._record_nested: bool = False  # True while inside an IF body
                                           # whose lines should be listed
                                           # individually (saved/restored on
                                           # each nested _process_block call)
        self._last_eval_undef: bool = False  # last _eval saw undefined sym
        self._if_stack: list = []  # for nested IFE/IFN (not used, we recurse)
        self._origin_set: bool = False
        # listing rows (pass 2 only):
        # list of (lineno, addr_or_None, [bytes], source_text)
        self.listing_lines: list = []
        # legacy alias kept for callers/tests
        self.listing_records: list = []

    # ── public API ────────────────────────────────────────────────────────────

    def define(self, name: str, value: int):
        """Pre-define a symbol (from command line -D)."""
        key = normalize_symbol(name)
        self.symbols[key] = value
        self.predefined.add(key)
        self.symbol_names.setdefault(key, set()).add(name.upper())

    def assemble_file(self, path: str) -> Emitter:
        with open(path, 'r', errors='replace') as f:
            source = f.read()
        return self.assemble(source)

    def assemble(self, source: str) -> Emitter:
        # Strip block comments: COMMENT delim … delim
        source = self._strip_block_comments(source)
        # Pass 1 — collect labels & equates
        self.pass_num = 1
        self.pc = 0
        self._origin_set = False
        self._cur_lineno = 1
        self._nesting = 0
        self._process_block(source, {}, nested=False)
        # Pass 2 — emit code
        self.pass_num = 2
        self.pc = 0
        self._origin_set = False
        self.emitter = Emitter()
        self.listing_lines = []
        self._cur_lineno = 1
        self._nesting = 0
        self._process_block(source, {}, nested=False)
        self.emitter.flush()
        return self.emitter

    # ── pre-processing ────────────────────────────────────────────────────────

    @staticmethod
    def _strip_block_comments(text: str) -> str:
        """Remove COMMENT <delim>…<delim> blocks."""
        result = []
        i = 0
        while i < len(text):
            # Check for COMMENT keyword
            m = re.match(r'[ \t]*COMMENT[ \t]+(\S)', text[i:], re.IGNORECASE)
            if m:
                delim = re.escape(m.group(1))
                # Skip to matching delimiter
                end = text.find(m.group(1), i + m.end())
                if end == -1:
                    break
                # preserve line count
                nl = text[i:end + 1].count('\n')
                result.append('\n' * nl)
                i = end + 1
            else:
                nl_pos = text.find('\n', i)
                if nl_pos == -1:
                    result.append(text[i:])
                    break
                result.append(text[i:nl_pos + 1])
                i = nl_pos + 1
        return ''.join(result)

    # ── block processor ───────────────────────────────────────────────────────

    def _process_block(self, text: str, local_params: dict,
                       nested: bool = True, expand_listing: bool = False):
        """Process a block of source.

        ``nested`` is False only for the outermost top-level pass over the
        original source.

        ``expand_listing`` requests that body lines be recorded individually
        in the listing — used for ``IF*`` bodies which are verbatim slices
        of the original source.  It is silently disabled if the parent
        context isn't itself recording (so an ``IF`` inside a macro / REPEAT
        / IRP / IRPC body doesn't break the parent's "macro suppression"
        rule, matching the behaviour of the ``SALL`` listing directive).

        Line-number tracking and the ``_record_nested`` flag are saved on
        entry and restored on exit so that the outer ``_process_block``
        loop can re-count line advances over the whole consumed slice and
        thus stay in sync with the original source line numbering.
        """
        saved_record = self._record_nested
        saved_lineno = self._cur_lineno
        if nested:
            parent_recorded = (self._nesting == 0) or saved_record
            self._nesting += 1
            # An IF body only "expands" in the listing if the parent
            # context was already recording (top-level or another
            # expanding-IF body).  This makes macro/REPEAT bodies
            # suppress nested IF expansion, matching SALL semantics.
            self._record_nested = bool(expand_listing and parent_recorded)
        # Track line numbers when this block is part of the original source
        # (top-level or an expanding IF body).
        track_lineno = (not nested) or self._record_nested
        try:
            pos = 0
            while pos < len(text):
                new_pos = skip_ws_nl(text, pos)
                if track_lineno:
                    self._cur_lineno += text[pos:new_pos].count('\n')
                pos = new_pos
                if pos >= len(text):
                    break
                new_pos = self._process_line(text, pos, local_params)
                if track_lineno:
                    self._cur_lineno += text[pos:new_pos].count('\n')
                pos = new_pos
        finally:
            if nested:
                self._nesting -= 1
                self._record_nested = saved_record
                # Restore _cur_lineno so the outer loop's own newline
                # count over the whole nested slice advances correctly
                # without double-counting body newlines.
                self._cur_lineno = saved_lineno

    def _extract_body(self, body_str: str) -> str:
        """Extract the assembly body from a possibly angle-bracketed string.

        Accepts MACRO-10's optional notations:

          IFx EXPR,<body>    ← standard
          IFx EXPR<body>     ← optional comma omitted before angle block
          IF1,<body>         ← bodyless directives may use leading comma
          IF1 <body>         ← or just whitespace
        """
        body_str = body_str.strip()
        if not body_str:
            return ''
        # Allow a leading comma (e.g.  IF1,<body>  or  IFE expr,<body>'s body
        # half once already split off)
        if body_str.startswith(','):
            body_str = body_str[1:].lstrip()
        if body_str.startswith('<'):
            inner, _ = read_angle_block(body_str, 0)
            return inner
        return body_str
        """Process one logical statement. Returns new pos."""
        pos = skip_ws(text, pos)
        if pos >= len(text):
            return pos

        # Skip comment-only lines
        if text[pos] == ';':
            return self._skip_to_eol(text, pos)

        # Skip blank lines
        if text[pos] == '\n':
            return pos + 1

        # ── Collect optional label ────────────────────────────────────────────
        label = None
        global_label = False
        label_start = pos

        # Try to match  LABELNAME:[:] or LABELNAME= 
        # (labels can contain $, %, ., digits except first char)
        m = re.match(r'([A-Za-z_.%$][A-Za-z0-9_.%$]*)\s*(::?)', text[pos:])
        if m:
            label = m.group(1)
            global_label = m.group(2) == '::'
            pos += m.end()
            pos = skip_ws(text, pos)
            if text[pos:pos+1] == '\n' or pos >= len(text) or text[pos] == ';':
                # Label-only line
                self._define_label(label, local_params)
                return self._skip_to_eol(text, pos)

        # ── Read mnemonic / directive name ────────────────────────────────────
        pos = skip_ws(text, pos)
        name_start = pos
        while pos < len(text) and (text[pos].isalnum() or text[pos] in '_.$%#@'):
            pos += 1
        name = text[name_start:pos].upper()

        if not name:
            # Could be a bare expression (emits a byte)
            if label:
                self._define_label(label, local_params)
            return self._skip_to_eol(text, pos)

        # ── Define label if present ───────────────────────────────────────────
        if label and name not in ('=', '=='):
            self._define_label(label, local_params)

        # ── Rest of line (raw) ────────────────────────────────────────────────
        pos = skip_ws(text, pos)
        raw_args, pos = self._read_rest_of_line(text, pos)
        raw_args = raw_args.strip()

        # ── Dispatch ──────────────────────────────────────────────────────────
        self._dispatch(name, raw_args, label, local_params)
        return pos

    def _dispatch(self, name: str, raw: str, label, local_params: dict):
        """Dispatch a statement by name."""
        # ── Symbol assignment ─────────────────────────────────────────────────
        if name in ('=', '=='):
            val = self._eval(raw, local_params)
            if label:
                self.symbols[label] = val
            return

        # Check if it's a label followed by  = expr  or  == expr
        # (handled already by _process_line, but just in case)

        # ── Assembler directives ──────────────────────────────────────────────
        uname = name.upper()

        if uname in ('TITLE','SUBTTL','PAGE','SALL','RADIX','SEARCH',
                     'PRINTX','XLIST','LIST','NLIST', 'END',
                     'PURGE','EXTERN','EXTERNAL','ENTRY','INTERN','INTERNAL',
                     'SIXBIT','HRRZ','HRLI','JRST','MOVEI','PJRST','PUTRST',
                     'CALL','TJSR','XWD_SKIP',
                     # MACRO-10 cross-reference control pseudo-ops (all dot-
                     # prefixed forms): no effect on code generation.
                     '.CREF', '.NCREF', '.XCREF', '.LIST', '.NLIST',
                     '.XLIST', '.LALL', '.SALL', '.XALL',
                     # Other rarely-used MACRO-10 listing controls
                     'LALL', 'XALL'):
            # No-op directives (or PDP-10 instructions we ignore for 6502).
            # NB: numeric arg of RADIX is *always* decimal in MACRO-10 (the
            # manual is explicit on this), regardless of the current radix.
            if uname == 'RADIX':
                try:
                    self.radix = int(raw.strip(), 10)
                except Exception:
                    pass
            if uname == 'PRINTX' and self.pass_num == 1:
                print(f"  [PRINTX] {raw.strip()}")
            if uname == 'PURGE':
                # Remove listed symbols from the table (rare; conservative).
                for nm in split_args(raw):
                    k = normalize_symbol(nm.strip())
                    if k and k not in self.predefined:
                        self.symbols.pop(k, None)
                        self.symbol_names.pop(k, None)
            return

        if uname in ('IFDEF', 'IFNDEF'):
            # IFDEF sym,<body>  (or  IFDEF sym<body>  — comma optional when
            # body is angle-bracketed, per MACRO-10 manual).
            raw = raw.strip()
            depth = 0
            split_at = -1
            body_at = -1
            for i, c in enumerate(raw):
                if c == '<' and depth == 0:
                    body_at = i
                    break
                if c == '<': depth += 1
                elif c == '>': depth -= 1
                elif c == ',' and depth == 0:
                    split_at = i
                    break
            if split_at != -1:
                sym_str  = raw[:split_at].strip()
                body_str = raw[split_at + 1:].strip()
            elif body_at != -1:
                sym_str  = raw[:body_at].strip()
                body_str = raw[body_at:].strip()
            else:
                return
            # sym may be angle-bracketed or plain ident
            if sym_str.startswith('<') and sym_str.endswith('>'):
                sym_name = sym_str[1:-1].strip()
            else:
                sym_name = sym_str
            sym_key = normalize_symbol(self._subst_params(sym_name.upper(), local_params))
            defined = sym_key in self.symbols
            take = (defined if uname == 'IFDEF' else not defined)
            if take:
                body = self._extract_body(body_str)
                self._process_block(body, local_params, expand_listing=True)
            return

        if uname == 'XWD':
            # XWD left,right — in M6502 context emit right-half low byte
            parts = split_args(raw)
            if len(parts) >= 2:
                val = self._eval(parts[1], local_params) & 0xFF
                self._emit(val)
            return

        if uname == 'ORG':
            addr = self._eval(raw, local_params)
            self.pc = addr
            if self.pass_num == 2:
                self.emitter.set_origin(addr)
            return

        if uname == 'BLOCK':
            # BLOCK n  — reserve n bytes (manual: "all n words initialised
            # to 0").  Implemented as a true reservation so the listing
            # doesn't show a long run of "00" bytes for large BLOCKs.  The
            # binary output still contains the implicit zeros via segment
            # zero-fill.
            n = self._eval(raw, local_params)
            if n < 0:
                n = 0
            if self.pass_num == 2:
                self.emitter.reserve(n)
            self.pc += n
            # Mark that any existing origin is now "moved" so a subsequent
            # _emit() will start a fresh segment at the new pc.
            self._origin_set = False
            return

        if uname == 'EXP':
            # EXP val[,val…]   — emit one byte per expression.
            #   EXP 144,128,0,0   → four bytes
            #   EXP(val)          → one byte (parenthesised single expr)
            arg = raw.strip()
            if arg.startswith('(') and arg.endswith(')'):
                arg = arg[1:-1]
            for piece in split_args(arg):
                piece = piece.strip()
                if not piece:
                    continue
                val = self._eval(piece, local_params)
                self._emit(val & 0xFF)
            return

        if uname == 'ADR':
            # ADR(expr) — emit 16-bit little-endian address
            arg = raw.strip()
            if arg.startswith('(') and arg.endswith(')'):
                arg = arg[1:-1]
            elif arg.startswith('<') and arg.endswith('>'):
                arg = arg[1:-1]
            val = self._eval(arg, local_params)
            self._emit(val & 0xFF)
            self._emit((val >> 8) & 0xFF)
            return

        if uname == 'DC':
            # DC"string" — emit ASCII bytes, last byte with high bit set
            raw2 = self._subst_params(raw, local_params)
            s = self._parse_string_arg(raw2)
            for i, c in enumerate(s):
                b = ord(c) & 0x7F
                if i == len(s) - 1:
                    b |= 0x80
                self._emit(b)
            return

        if uname == 'DT':
            # DT"string" — emit ASCII bytes (no high-bit marking)
            raw2 = self._subst_params(raw, local_params)
            s = self._parse_string_arg(raw2)
            for c in s:
                self._emit(ord(c) & 0x7F)
            return

        if uname == 'ACRLF':
            self._emit(13)
            self._emit(10)
            return

        if uname == 'DEFINE':
            self._handle_define(raw)
            return

        if uname in ('IFE','IFN','IFG','IFL','IFGE','IFLE'):
            self._handle_conditional(uname, raw, local_params)
            return

        if uname == 'IFDIF':
            self._handle_ifdif(raw, local_params, equal=False)
            return

        if uname == 'IFIDN':
            self._handle_ifdif(raw, local_params, equal=True)
            return

        if uname == 'IF1':
            # IF1,<body> — execute only in pass 1
            body = self._extract_body(raw)
            if body and self.pass_num == 1:
                self._process_block(body, local_params, expand_listing=True)
            return

        if uname == 'IF2':
            body = self._extract_body(raw)
            if body and self.pass_num == 2:
                self._process_block(body, local_params, expand_listing=True)
            return

        if uname == 'REPEAT':
            self._handle_repeat(raw, local_params)
            return

        if uname == 'IRPC':
            self._handle_irpc(raw, local_params)
            return

        if uname == 'IRP':
            self._handle_irp(raw, local_params)
            return

        # ── 6502 instructions ─────────────────────────────────────────────────
        if uname in ALL_MNEMONICS:
            self._encode_instruction(uname, raw, local_params)
            return

        # ── Macro call ────────────────────────────────────────────────────────
        if uname in self.macros:
            self._expand_macro(uname, raw, local_params)
            return

        # ── Bare expression (emit byte) ───────────────────────────────────────
        # ── Bare expression (emit byte) ─────────────────────────────────────
        # Reconstruct the "bare expression" from name + raw
        full_expr = name + (' ' + raw if raw else '')
        # Check for  SYM = EXPR  or  SYM == EXPR  forms
        m = re.match(r'^([A-Za-z_.%$][A-Za-z0-9_.%$]*)\s*(==?)\s*(.+)$',
                     full_expr.strip())
        if m:
            sym, op, expr = m.group(1), m.group(2), m.group(3)
            val = self._eval(expr, local_params)
            self.symbols[normalize_symbol(sym)] = val
            return

        # Bare expression following an unrecognised mnemonic.  Both
        # passes must always emit exactly one byte so PC stays
        # synchronised; an undefined symbol contributes 0 and produces a
        # pass-2 warning.  Real MACRO-10 listing pseudo-ops we don't
        # model (e.g. .CREF, .XCREF, .LIST, …) are intercepted as
        # no-ops earlier in this routine, so they never reach here.
        stripped = full_expr.strip()
        try:
            val = self._eval(stripped, local_params)
        except AsmError:
            val = 0
            if self.pass_num == 2 and self.verbose:
                print(f"  [warn] undefined in expression {stripped!r}; "
                      f"emitting 0")
        if self.pass_num == 2 and self._last_eval_undef and self.verbose:
            # purely defined-elsewhere check: warn once in pass 2 if any
            # part of the expression referenced an undefined symbol.
            print(f"  [warn] expression {stripped!r} references "
                  f"undefined symbol")
        self._emit(val & 0xFF)

    # ── Label definition ───────────────────────────────────────────────────────

    def _define_label(self, name: str, local_params: dict):
        # Substitute local params in label name (for %Q etc.)
        name = self._subst_params(name, local_params)
        if self.pass_num == 1:
            key = normalize_symbol(name)
            self.symbols[key] = self.pc
            self.symbol_names.setdefault(key, set()).add(name.upper())
        # In pass 2 we don't redefine (use pass-1 values for forward refs)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _skip_to_eol(self, text: str, pos: int) -> int:
        while pos < len(text) and text[pos] != '\n':
            pos += 1
        if pos < len(text):
            pos += 1  # consume newline
        return pos

    def _read_rest_of_line(self, text: str, pos: int) -> tuple:
        """Read to end of line respecting <> depth. Strip comments."""
        depth = 0
        buf = []
        while pos < len(text):
            c = text[pos]
            if c == ';' and depth == 0:
                pos = self._skip_to_eol(text, pos)
                break
            if c == '\n' and depth == 0:
                pos += 1
                break
            if c == '<':
                depth += 1
            elif c == '>':
                depth -= 1
                if depth < 0:
                    # stray '>' (extra closing bracket) — consume it and stop
                    pos += 1
                    break
            buf.append(c)
            pos += 1
        return ''.join(buf), pos

    def _parse_string_arg(self, raw: str) -> str:
        """Extract string content from  "..."  or  < >  argument."""
        s = raw.strip()
        if not s:
            return ""
        # unwrap angle brackets
        if s.startswith('<') and s.endswith('>'):
            s = s[1:-1]
        # unwrap surrounding parentheses which are used in macros like DC(A)
        if s.startswith('(') and s.endswith(')'):
            s = s[1:-1]
        # unwrap quotes
        if s.startswith('"') and s.endswith('"'):
            return s[1:-1]
        if s.startswith('"'):
            return s[1:]
        return s
        s = raw.strip()
        if s.startswith(','):
            s = s[1:].lstrip()
        if s.startswith('<'):
            inner, _ = read_angle_block(s, 0)
            return inner
        return s

    def _eval(self, expr: str, local_params: dict) -> int:
        """Evaluate expression, substituting local macro parameters first."""
        expr = self._subst_params(expr.strip(), local_params)
        e = ExprEval(self.symbols, self.pc, self.radix, self.pass_num)
        try:
            val = e.eval(expr)
        except AsmError:
            self._last_eval_undef = True
            if self.pass_num == 1:
                return 0   # undefined symbols / div-by-zero OK in pass 1
            raise
        self._last_eval_undef = e.had_undef
        return val

    def _subst_params(self, text: str, params: dict) -> str:
        """Substitute macro formal parameters in text (longest match first)."""
        if not params:
            return text
        # Sort by length descending to handle overlapping names
        for name in sorted(params, key=len, reverse=True):
            val = params[name]
            # Replace whole-word occurrences of the parameter
            text = re.sub(r'(?<![A-Za-z0-9_.%$])' + re.escape(name) +
                          r'(?![A-Za-z0-9_.%$])', lambda m, v=val: v, text)
        return text

    def _emit(self, byte: int):
        if self.pass_num == 2:
            if not self._origin_set:
                self.emitter.set_origin(self.pc)
                self._origin_set = True
            self.emitter.emit(byte & 0xFF)
        self.pc += 1

    def _emit_word(self, val: int):
        self._emit(val & 0xFF)
        self._emit((val >> 8) & 0xFF)

    # ── DEFINE / macro handling ───────────────────────────────────────────────

    def _handle_define(self, raw: str):
        """Parse DEFINE name (p1,p2,...),<body> and store macro."""
        raw = raw.strip()
        # name
        m = re.match(r'([A-Za-z_.%$][A-Za-z0-9_.%$]*)\s*', raw)
        if not m:
            return
        mname = m.group(1).upper()
        pos = m.end()
        # optional (params)
        params = []
        if pos < len(raw) and raw[pos] == '(':
            end = raw.find(')', pos)
            if end != -1:
                plist = raw[pos + 1:end]
                params = [p.strip().upper() for p in plist.split(',') if p.strip()]
                pos = end + 1
        pos = skip_ws(raw, pos)
        # comma before body
        if pos < len(raw) and raw[pos] == ',':
            pos += 1
        pos = skip_ws(raw, pos)
        # body in <...>
        if pos < len(raw) and raw[pos] == '<':
            body, _ = read_angle_block(raw, pos)
        else:
            body = raw[pos:]
        self.macros[mname] = (params, body)

    def _expand_macro(self, name: str, raw_args: str, outer_params: dict):
        """Expand a user-defined macro call."""
        params, body = self.macros[name]
        # substitute outer params in raw_args first
        raw_args = self._subst_params(raw_args, outer_params)
        # parse actual arguments
        actual = self._parse_macro_args(raw_args, len(params))
        # build local_params dict
        local = {}
        for i, p in enumerate(params):
            local[p] = actual[i] if i < len(actual) else ''
        # generate unique local-label suffix
        self._local_ctr += 1
        lctr = self._local_ctr
        # rename %X local labels uniquely
        body_expanded = self._rename_local_labels(body, lctr)
        # Also substitute any outer local params in body
        body_expanded = self._subst_params(body_expanded, outer_params)
        # process
        self._process_block(body_expanded, local)

    def _parse_macro_args(self, raw: str, expected: int) -> list:
        """Parse comma-separated args, respecting <> depth."""
        raw = raw.strip()
        if not raw:
            return []
        # If the whole thing is angle-bracketed, unwrap
        if raw.startswith('<') and raw.endswith('>'):
            raw = raw[1:-1]
        args = split_args(raw)
        # Unwrap individual <arg>
        result = []
        for a in args:
            a = a.strip()
            if a.startswith('<') and a.endswith('>'):
                a = a[1:-1]
            # unwrap quoted args as MACRO-10 passes bare string
            if a.startswith('"') and a.endswith('"'):
                a = a[1:-1]
            result.append(a)
        return result

    @staticmethod
    def _rename_local_labels(body: str, ctr: int) -> str:
        """Replace %NAME local labels/refs with unique %NAME_ctr."""
        def repl(m):
            return f'%{m.group(1)}_{ctr}'
        return re.sub(r'%([A-Za-z][A-Za-z0-9]*)', repl, body)

    # ── Conditional assembly ──────────────────────────────────────────────────

    def _handle_conditional(self, kind: str, raw: str, local_params: dict):
        """IFE/IFN/IFG/IFL/IFGE/IFLE expr,<body>

        MACRO-10 also permits omitting the comma when ``<body>`` is
        angle-bracketed, e.g. ``IFE EXPR<body>``.
        """
        raw = raw.strip()
        # Find the first top-level comma OR opening angle that ends EXPR.
        depth = 0
        split_at = -1
        body_at = -1
        for i, c in enumerate(raw):
            if c == '<' and depth == 0:
                body_at = i
                break
            if c == '<':
                depth += 1
            elif c == '>':
                depth -= 1
            elif c == ',' and depth == 0:
                split_at = i
                break
        if split_at != -1:
            expr_str = raw[:split_at].strip()
            body_str = raw[split_at + 1:].strip()
        elif body_at != -1:
            expr_str = raw[:body_at].strip()
            body_str = raw[body_at:].strip()
        else:
            return
        # Comparisons in MACRO-10 are SIGNED.  Our evaluator returns a
        # 16-bit unsigned value; sign-extend the high bit so negative
        # values compare correctly for IFG / IFL / IFGE / IFLE.
        val = self._eval(expr_str, local_params)
        sval = val - 0x10000 if val & 0x8000 else val
        take = False
        if   kind == 'IFE':  take = (val == 0)
        elif kind == 'IFN':  take = (val != 0)
        elif kind == 'IFG':  take = (sval >  0)
        elif kind == 'IFL':  take = (sval <  0)
        elif kind == 'IFGE': take = (sval >= 0)
        elif kind == 'IFLE': take = (sval <= 0)
        if take:
            body = self._extract_body(body_str)
            self._process_block(body, local_params, expand_listing=True)

    def _handle_ifdif(self, raw: str, local_params: dict, equal: bool):
        """IFDIF <a>,<b>,<body>  — assemble body if a != b (or == for IFIDN)."""
        raw = raw.strip()
        # Parse three angle-bracketed args
        parts = []
        pos = 0
        while pos < len(raw) and len(parts) < 3:
            pos = skip_ws(raw, pos)
            if pos >= len(raw):
                break
            if raw[pos] == '<':
                inner, pos = read_angle_block(raw, pos)
                parts.append(inner)
            elif raw[pos] == ',':
                pos += 1
            else:
                # read until comma
                end = pos
                while end < len(raw) and raw[end] not in ',<':
                    end += 1
                parts.append(raw[pos:end].strip())
                pos = end
        if len(parts) < 2:
            return
        a = self._subst_params(parts[0], local_params)
        b = self._subst_params(parts[1], local_params)
        take = (a != b) if not equal else (a == b)
        if take and len(parts) >= 3:
            self._process_block(parts[2], local_params, expand_listing=True)

    def _handle_repeat(self, raw: str, local_params: dict):
        """REPEAT n,<body>"""
        raw = raw.strip()
        # find comma
        depth = 0
        split_at = -1
        for i, c in enumerate(raw):
            if c == '<': depth += 1
            elif c == '>': depth -= 1
            elif c == ',' and depth == 0:
                split_at = i
                break
        if split_at == -1:
            return
        n = self._eval(raw[:split_at], local_params)
        body_str = raw[split_at + 1:].strip()
        body = self._extract_body(body_str)
        for _ in range(max(0, n)):
            self._local_ctr += 1
            lctr = self._local_ctr
            b = self._rename_local_labels(body, lctr)
            self._process_block(b, local_params)

    def _handle_irpc(self, raw: str, local_params: dict):
        """IRPC var,<string> — iterate var over chars of string, expand body."""
        # Format (after DT param substitution): var,<IFDIF <var_val><">,<EXP "var_val">>
        # In practice, we handle this inline.
        raw = raw.strip()
        # Parse: varname , <string_to_iterate_over> , <body>
        # OR: varname , <body_that_contains_everything>
        # Find the iteration var name
        m = re.match(r'([A-Za-z_.%$][A-Za-z0-9_.%$]*)\s*,\s*', raw)
        if not m:
            return
        var = m.group(1).upper()
        rest = raw[m.end():]
        # The rest should be <string>,<body> OR just <body>
        if not rest.startswith('<'):
            return
        # The first angle block might be the string or the body
        first, pos = read_angle_block(rest, 0)
        rest2 = rest[pos:].lstrip()
        if rest2.startswith(',') and rest2[1:].lstrip().startswith('<'):
            # first = string to iterate, body = next block
            string_to_iter = first
            # substitute local params in string
            string_to_iter = self._subst_params(string_to_iter, local_params)
            rest2 = rest2[1:].lstrip()
            body, _ = read_angle_block(rest2, 0)
        else:
            # first = body, but we need to know what to iterate over
            # This is the DT macro pattern: var has the string value from outer params
            if var in local_params:
                string_to_iter = local_params[var]
                string_to_iter = self._subst_params(string_to_iter, local_params)
            else:
                string_to_iter = first
            body = first
        # Now iterate each character
        for ch in string_to_iter:
            new_local = dict(local_params)
            new_local[var] = ch
            self._local_ctr += 1
            b = self._rename_local_labels(body, self._local_ctr)
            self._process_block(b, new_local)

    def _handle_irp(self, raw: str, local_params: dict):
        """IRP var,(item1,item2,...),<body>"""
        raw = raw.strip()
        m = re.match(r'([A-Za-z_.%$][A-Za-z0-9_.%$]*)\s*,\s*', raw)
        if not m:
            return
        var = m.group(1).upper()
        rest = raw[m.end():]
        # list in (...)
        if rest.startswith('('):
            end = rest.find(')')
            if end == -1:
                return
            items_str = rest[1:end]
            rest = rest[end + 1:].lstrip().lstrip(',').lstrip()
        else:
            return
        items = [i.strip() for i in items_str.split(',')]
        body = self._extract_body(rest)
        for item in items:
            new_local = dict(local_params)
            new_local[var] = item
            self._local_ctr += 1
            b = self._rename_local_labels(body, self._local_ctr)
            self._process_block(b, new_local)

    # ── 6502 instruction encoding ─────────────────────────────────────────────

    def _encode_instruction(self, mnem: str, raw: str,
                            local_params: dict):
        """Encode a 6502 instruction (or M6502 variant) to bytes."""
        raw = self._subst_params(raw, local_params)
        raw = raw.strip()

        # ── Immediate-mode variants (LDAI, CMPI, etc.) ────────────────────────
        if mnem in IMM_MNEMONICS:
            base = IMM_MNEMONICS[mnem]
            val = self._eval(raw, local_params)
            op = OPCODES.get((base, 'imm'))
            if op is None:
                raise AsmError(f"no immediate mode for {base}")
            self._emit(op)
            self._emit(val & 0xFF)
            return

        # ── Indirect-indexed Y variants (LDADY, STADY, etc.) ─────────────────
        if mnem in INY_MNEMONICS:
            base = INY_MNEMONICS[mnem]
            zp = self._eval(raw, local_params)
            op = OPCODES.get((base, 'iny'))
            if op is None:
                raise AsmError(f"no (zp),Y mode for {base}")
            self._emit(op)
            self._emit(zp & 0xFF)
            return

        # ── JMPD — indirect JMP ───────────────────────────────────────────────
        if mnem == 'JMPD':
            addr = self._eval(raw, local_params)
            self._emit(OPCODES[('JMP', 'ind')])
            self._emit_word(addr)
            return

        # ── Implied (no operand) ──────────────────────────────────────────────
        if mnem in IMPLIED:
            op = OPCODES.get((mnem, 'imp'))
            if op is not None:
                self._emit(op)
                return

        # ── Branches (relative) ───────────────────────────────────────────────
        if mnem in BRANCHES:
            target = self._eval(raw, local_params)
            op = OPCODES[(mnem, 'rel')]
            self._emit(op)
            offset = (target - (self.pc + 1)) & 0xFFFF
            if offset > 127 and offset < 0xFF80:
                if self.pass_num == 2:
                    raise AsmError(
                        f"branch to {target:#06x} out of range from {self.pc:#06x}")
                self._emit(0)
            else:
                self._emit(offset & 0xFF)
            return

        # ── Accumulator-mode shift / rotate ──────────────────────────────────
        if mnem in ACC_CAPABLE:
            # 'A' or 'A,' treated as accumulator mode; blank also = accumulator
            arg = raw.strip().rstrip(',').strip()
            if arg == '' or arg.upper() == 'A':
                op = OPCODES.get((mnem, 'acc'))
                if op is not None:
                    self._emit(op)
                    return
            # fall through to memory addressing

        # ── JSR / JMP (always absolute) ───────────────────────────────────────
        if mnem == 'JSR':
            addr = self._eval(raw, local_params)
            self._emit(OPCODES[('JSR', 'abs')])
            self._emit_word(addr)
            return

        if mnem == 'JMP':
            addr = self._eval(raw, local_params)
            self._emit(OPCODES[('JMP', 'abs')])
            self._emit_word(addr)
            return

        # ── General addressing (zp / abs / indexed) ───────────────────────────
        if raw == '':
            # Implied (catches things like INSTR with no arg)
            op = OPCODES.get((mnem, 'imp'))
            if op is not None:
                self._emit(op)
                return
            raise AsmError(f"unexpected empty operand for {mnem}")

        # Split on comma (depth-aware) to detect indexed mode
        parts = split_args(raw)
        addr_str = parts[0].strip()
        index = parts[1].strip().upper() if len(parts) > 1 else ''

        # Strip outer angle brackets from address
        if addr_str.startswith('<') and addr_str.endswith('>'):
            addr_str = addr_str[1:-1]

        addr_val = self._eval(addr_str, local_params)

        if index == 'X':
            if 0 <= addr_val <= 255:
                mode = 'zpx'
            else:
                mode = 'abx'
            # LDX and STX use zpy not zpx — handle
            if mnem == 'LDX': mode = 'aby' if addr_val > 255 else 'zpy'
            op = OPCODES.get((mnem, mode))
            if op is None:
                # try abs
                op = OPCODES.get((mnem, 'abx'))
            if op is None:
                raise AsmError(f"no {mode} mode for {mnem}")
            self._emit(op)
            if mode in ('zpx', 'zpy'):
                self._emit(addr_val & 0xFF)
            else:
                self._emit_word(addr_val)
            return

        if index == 'Y':
            if mnem in ('LDX', 'STX') and 0 <= addr_val <= 255:
                mode = 'zpy'
                self._emit(OPCODES[(mnem, mode)])
                self._emit(addr_val & 0xFF)
            else:
                mode = 'aby'
                op = OPCODES.get((mnem, mode))
                if op is None:
                    raise AsmError(f"no aby mode for {mnem}")
                self._emit(op)
                self._emit_word(addr_val)
            return

        # No index: zp or absolute
        if 0 <= addr_val <= 255:
            op = OPCODES.get((mnem, 'zp'))
            if op is not None:
                self._emit(op)
                self._emit(addr_val & 0xFF)
                return
        # Use absolute
        op = OPCODES.get((mnem, 'abs'))
        if op is not None:
            self._emit(op)
            self._emit_word(addr_val)
            return

        # Last resort: try zp anyway
        op = OPCODES.get((mnem, 'zp'))
        if op is not None:
            self._emit(op)
            self._emit(addr_val & 0xFF)
            return

        raise AsmError(f"cannot encode {mnem} {raw!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Handle "name = expr" lines that appear as part of the statement flow
# (These appear at the TOP LEVEL as   SYMBOL = VALUE  or  SYMBOL == VALUE)
# ─────────────────────────────────────────────────────────────────────────────

# The _process_line method needs to detect  SYM = expr  or  SYM == expr
# We handle this inside _process_line: after reading "name", check if next
# token is = or ==

def _process_line_patched(self, text: str, pos: int,
                           local_params: dict) -> int:
    """
    Process one logical statement.

    MACRO-10 line grammar:
      [LABEL[:]  ]  MNEMONIC  [args]   ; comment
      SYMBOL = EXPR
      SYMBOL == EXPR
      bare-expr  (emits a byte)

    All listing-record bookkeeping is done here at one point, gated on
    ``self._nesting == 0`` (or inside an expand_listing block) so that
    nested macro / REPEAT bodies don't double-record bytes that the parent
    statement already attributes.
    """
    record = (self.pass_num == 2 and
              (self._nesting == 0 or self._record_nested))

    # Find start of physical source line for nicer listing src text
    src_line_start = pos
    while src_line_start > 0 and text[src_line_start - 1] != '\n':
        src_line_start -= 1
    rec_lineno = self._cur_lineno
    rec_start_pc = self.pc
    rec_before_listing = len(self.emitter.listing) if self.emitter else 0
    rec_records_before = len(self.listing_lines)
    rec_had_label = [False]   # closure-mutable

    def _record(end_pos):
        if not record:
            return
        # If nested processing recorded its own listing rows during dispatch,
        # this statement is a "header" (e.g. IFE/IFN that took its body):
        # don't double-count the body's bytes here, just record the directive
        # source line itself.  Place it BEFORE the body rows.
        nested_added = (len(self.listing_lines) > rec_records_before)
        src = text[src_line_start:end_pos].rstrip('\n').rstrip('\r')
        if nested_added:
            # Parent IF directive: show only its first physical source line;
            # the body lines are already recorded separately.
            bytes_out = []
            addr = None
            nl = src.find('\n')
            if nl >= 0:
                src = src[:nl].rstrip('\r')
        else:
            bytes_out = [b for _, b in
                         self.emitter.listing[rec_before_listing:]]
            # Show the address column when bytes were emitted, when the PC
            # advanced silently (e.g. BLOCK reserves space without adding
            # listing bytes), or when this is a label-only line (the label
            # address is meaningful to the reader).
            if bytes_out or self.pc != rec_start_pc or rec_had_label[0]:
                addr = rec_start_pc
            else:
                addr = None
        self.listing_lines.insert(rec_records_before,
                                  (rec_lineno, addr, bytes_out, src))

    pos0 = pos
    pos = skip_ws(text, pos)
    if pos >= len(text):
        return pos
    if text[pos] == '\n':
        # blank line — record (so listing line numbers stay aligned) only if
        # there was non-whitespace; otherwise drop it
        return pos + 1
    if text[pos] == ';':
        # comment-only line — record with no bytes so the comment is shown
        new_pos = self._skip_to_eol(text, pos)
        _record(new_pos)
        return new_pos

    start = pos  # save for bare-expr fallback

    # ── Read first token (may be label, symbol-name, or mnemonic) ────────────
    id_start = pos
    while pos < len(text) and (text[pos].isalnum() or text[pos] in '._$%#@'):
        pos += 1
    ident = text[id_start:pos]

    if not ident:
        # Non-identifier start: bare char literal, number, etc. → emit byte.
        # If the expression involves an undefined symbol, both passes emit
        # 0 (rather than pass 1 emitting 0 and pass 2 silently skipping)
        # so the PC stays synchronised across passes.
        raw_rest, pos = self._read_rest_of_line(text, start)
        raw_rest = raw_rest.strip()
        if raw_rest:
            try:
                val = self._eval(raw_rest, local_params)
            except AsmError:
                val = 0
                if self.pass_num == 2 and self.verbose:
                    print(f"  [warn] undefined in expression "
                          f"{raw_rest!r}; emitting 0")
            self._emit(val & 0xFF)
        _record(pos)
        return pos

    pos = skip_ws(text, pos)     # skip optional whitespace

    # ── Symbol assignment:  IDENT = EXPR  or  IDENT == EXPR ──────────────────
    if pos < len(text) and text[pos] == '=':
        pos += 1
        if pos < len(text) and text[pos] == '=':
            pos += 1  # consume second '='
        expr_str, pos = self._read_rest_of_line(text, pos)
        expr_str = expr_str.strip()
        expr_str = self._subst_params(expr_str, local_params)
        val = self._eval(expr_str, local_params)
        sym = self._subst_params(ident.upper(), local_params)
        key = normalize_symbol(sym)
        # Do not allow source assignments to overwrite symbols set via -D
        if key in getattr(self, 'predefined', set()):
            if self.verbose:
                print(f"Skipping source assignment of pre-defined symbol {sym}")
            _record(pos)
            return pos
        self.symbols[key] = val
        self.symbol_names.setdefault(key, set()).add(sym)
        # Record with the assigned value as "address" column (per DEC listing
        # convention for equates: the value is shown in the addr field).
        if record:
            src = text[src_line_start:pos].rstrip('\n').rstrip('\r')
            # "value" column — show the equate value
            self.listing_lines.append((rec_lineno, val, [], src))
        return pos

    # ── Label definition:  IDENT:  or  IDENT:: ───────────────────────────────
    label = None
    if pos < len(text) and text[pos] == ':':
        label = self._subst_params(ident.upper(), local_params)
        rec_had_label[0] = True
        if self.pass_num == 1:
            key = normalize_symbol(label)
            self.symbols[key] = self.pc
            self.symbol_names.setdefault(key, set()).add(label)
        pos += 1
        if pos < len(text) and text[pos] == ':':
            pos += 1  # global label (treated same as local for us)
        pos = skip_ws(text, pos)
        # Label-only line?
        if pos >= len(text) or text[pos] in (';\n'):
            new_pos = self._skip_to_eol(text, pos)
            _record(new_pos)
            return new_pos
        # Now read the mnemonic that follows the label
        name_start = pos
        while pos < len(text) and (text[pos].isalnum() or text[pos] in '._$%#@'):
            pos += 1
        name = text[name_start:pos].upper()
        if not name:
            new_pos = self._skip_to_eol(text, pos)
            _record(new_pos)
            return new_pos
        pos = skip_ws(text, pos)
        # Symbol assignment after label?  "LBL: SYM = EXPR" is not common but
        # handle "LBL=expr" via the earlier branch.
        raw_rest, pos = self._read_rest_of_line(text, pos)
        self._dispatch(name, raw_rest.strip(), label, local_params)
        _record(pos)
        return pos

    # ── No label: the first ident IS the mnemonic/directive ──────────────────
    name = ident.upper()
    raw_rest, pos = self._read_rest_of_line(text, pos)
    self._dispatch(name, raw_rest.strip(), None, local_params)
    _record(pos)
    return pos


# Monkey-patch the corrected method
Assembler._process_line = _process_line_patched


# ─────────────────────────────────────────────────────────────────────────────
# Intel HEX / Binary output helpers
# ─────────────────────────────────────────────────────────────────────────────
def write_output(emitter: Emitter, path: str, fmt: str):
    if fmt == 'ihex':
        data = emitter.to_ihex()
        with open(path, 'w') as f:
            f.write(data)
        print(f"Wrote Intel HEX: {path}")
    else:
        data = emitter.to_binary()
        with open(path, 'wb') as f:
            f.write(data)
        lo = min(a for a, _ in emitter.segments) if emitter.segments else 0
        hi = max(a + len(d) for a, d in emitter.segments) if emitter.segments else 0
        print(f"Wrote binary: {path}  ({len(data)} bytes, "
              f"${lo:04X}–${hi - 1:04X})")


def print_listing(emitter: Emitter, asm, file=None):
    """Print a hex DEC-MACRO style assembly listing.

    Adapted to the 6502: 16-bit hex address column (instead of MACRO-10's
    18-bit octal), 8-bit hex byte column (instead of 36-bit words).

        LLLLL  AAAA  BB BB BB BB    SOURCE-LINE
        LLLLL  VVVV                 SYM == VALUE          (equate)
        LLLLL                       SOURCE-LINE           (no-emit directive)

    If a single source statement emitted more than 4 bytes, continuation
    listing lines show successive (addr, bytes) groups.  If the statement
    spans multiple physical source lines (e.g. an IF<…multi-line body…>),
    each physical source line is printed on its own listing line, aligned
    with any matching continuation bytes column.
    """
    if file is None:
        file = sys.stdout

    BYTES_PER_LINE = 4
    LN_W   = 5      # line-number column
    ADDR_W = 4      # 16-bit hex address
    # 4 bytes × ("BB" + space) -1 = 11 cols
    BYTES_W = BYTES_PER_LINE * 3 - 1

    def _row(lineno, addr_field, byte_field, src_field=""):
        ln = f"{lineno:>{LN_W}}" if lineno else " " * LN_W
        af = (addr_field if addr_field else "").ljust(ADDR_W)
        bf = (byte_field or "").ljust(BYTES_W)
        return f"{ln}  {af}  {bf}  {src_field}".rstrip()

    print(file=file)
    print("Assembly listing:", file=file)
    print(file=file)
    print(f"{'LINE':>{LN_W}}  {'ADDR':<{ADDR_W}}  {'BYTES':<{BYTES_W}}  "
          f"SOURCE", file=file)
    print("-" * 78, file=file)

    rows = getattr(asm, 'listing_lines', None) or []

    for lineno, addr, bytes_out, src in rows:
        # Split source into physical lines for display
        src_lines = src.replace('\r', '').split('\n') if src else ['']
        # Pre-compute byte chunks and their addresses
        chunks = []
        if bytes_out:
            cur = addr & 0xFFFF
            i = 0
            while i < len(bytes_out):
                chunk = bytes_out[i:i + BYTES_PER_LINE]
                chunks.append((cur, chunk))
                cur = (cur + len(chunk)) & 0xFFFF
                i += BYTES_PER_LINE
        else:
            chunks = []

        # Total lines is max(len(src_lines), len(chunks))
        total = max(len(src_lines), len(chunks), 1)

        for i in range(total):
            ln  = lineno if i == 0 else 0
            # Address column: equate value on first line if no bytes,
            # otherwise the chunk's address.
            if i < len(chunks):
                af = f"{chunks[i][0]:04X}"
                bf = ' '.join(f"{b:02X}" for b in chunks[i][1])
            else:
                if i == 0 and not bytes_out and addr is not None:
                    af = f"{addr & 0xFFFF:04X}"  # equate value
                else:
                    af = ""
                bf = ""
            sf = src_lines[i] if i < len(src_lines) else ""
            print(_row(ln, af, bf, sf), file=file)


def print_symbol_table(asm, file=None):
    """Print the symbol table in hex, sorted alphabetically.

    Mimics the MACRO-10 cross-reference / symbol table at the end of a
    listing, but uses 16-bit hex values instead of octal.
    """
    if file is None:
        file = sys.stdout
    print(file=file)
    print("Symbol table:", file=file)
    print(file=file)
    # Build (display-name -> value) dict, preferring the longest original name
    # captured for each normalized key.
    items = []
    for key, val in asm.symbols.items():
        names = asm.symbol_names.get(key, {key})
        # pick longest original name (most descriptive)
        name = max(names, key=len)
        items.append((name, val))
    items.sort(key=lambda kv: kv[0])
    # Print 3 per line for compactness
    COLS = 3
    COLW = 26
    line = []
    for i, (name, val) in enumerate(items):
        cell = f"{name:<14s}= {val & 0xFFFF:04X}"
        line.append(cell.ljust(COLW))
        if (i + 1) % COLS == 0:
            print('  '.join(line), file=file)
            line = []
    if line:
        print('  '.join(line), file=file)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='MACRO-10 / M6502 cross-assembler')
    parser.add_argument('input', help='source file (m6502.asm)')
    parser.add_argument('-o', '--output', help='output file')
    parser.add_argument('-f', '--format', choices=['bin', 'ihex'],
                        default='bin', help='output format (default: bin)')
    parser.add_argument('-D', '--define', action='append', default=[],
                        metavar='SYM[=VAL]',
                        help='pre-define symbol; -D REALIO=4')
    parser.add_argument('-l', '--listing',
                        help='write hex listing to FILE (default: stdout '
                             'when -v is given)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='print listing and symbols on stdout')
    args = parser.parse_args()

    outpath = args.output or os.path.splitext(args.input)[0] + (
        '.hex' if args.format == 'ihex' else '.bin')

    asm = Assembler(verbose=args.verbose)

    # Apply -D definitions
    for d in args.define:
        if '=' in d:
            sym, val = d.split('=', 1)
            asm.define(sym.strip().upper(), int(val.strip(), 0))
        else:
            asm.define(d.strip().upper(), 1)

    print("Pass 1…")
    try:
        emitter = asm.assemble_file(args.input)
    except AsmError as e:
        print(f"Assembly failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        import traceback
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)

    print(f"Pass 2 complete. Symbols defined: {len(asm.symbols)}")
    if args.listing:
        with open(args.listing, 'w') as f:
            print_listing(emitter, asm, file=f)
            print_symbol_table(asm, file=f)
        print(f"Wrote listing: {args.listing}")
    elif args.verbose:
        print_listing(emitter, asm)
        print_symbol_table(asm)

    write_output(emitter, outpath, args.format)


if __name__ == '__main__':
    main()
