import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from m6502_to_ca65 import Translator, main


class TranslateCa65Tests(unittest.TestCase):
    def test_simple_instruction_conversion(self):
        src = "LDAI 42\nLDADY PTR\nJMPD TARGET\n"
        out = Translator().translate(src).text
        self.assertIn("LDA #42", out)
        self.assertIn("LDA (PTR),Y", out)
        self.assertIn("JMP (TARGET)", out)

    def test_directive_conversion(self):
        src = "ORG ^O20000\nFOO==1\nBAR=2\n"
        out = Translator().translate(src).text
        self.assertIn(".org 8192", out)
        self.assertIn("FOO .set 1", out)
        self.assertIn("BAR .set 2", out)

    def test_if_conversion(self):
        src = "IFE 0,<LDAI 1>\n"
        out = Translator().translate(src).text
        self.assertIn(".if 0 = 0", out)
        self.assertIn(".endif", out)

    def test_data_directives_are_ca65_friendly(self):
        src = 'DCI"END"\nBLOCK 3\nDT "OK"\n'
        out = Translator().translate(src).text
        self.assertIn(".byte 'E', 'N', 'D'|$80", out)
        self.assertIn(".res 3", out)
        self.assertIn('.byte "OK"', out)

    def test_single_char_double_quotes_become_char_literals(self):
        src = 'LDAI " "\nDT "T"\n'
        out = Translator().translate(src).text
        self.assertIn("LDA #' '", out)
        self.assertIn(".byte 'T'", out)

    def test_include_handling(self):
        src = "SEARCH M6502\n"
        out = Translator(preserve_includes=True).translate(src).text
        self.assertIn('.include "M6502"', out)

    def test_symbolic_alias_redefinition_inserts_undef(self):
        src = "FOO=BAR\nFOO=BAZ\n"
        out = Translator().translate(src).text
        self.assertIn(".define FOO BAR", out)
        self.assertIn(".undef FOO", out)
        self.assertIn(".define FOO BAZ", out)

    def test_label_shadowing_macro_alias_inserts_undef(self):
        src = "FOO=BAR\nFOO: NOP\n"
        out = Translator().translate(src).text
        self.assertNotIn(".define FOO BAR", out)
        self.assertIn("FOO: NOP", out)

    def test_repeat_block_maps_to_repeat_directives(self):
        src = "IFE 1,<\nREPEAT 2,\nLDAI 0\n>\n"
        out = Translator().translate(src).text
        self.assertIn(".repeat 2", out)
        self.assertIn(".endrepeat", out)

    def test_trailing_operand_comma_is_removed(self):
        src = "LDA TABLE,X,\n"
        out = Translator().translate(src).text
        self.assertIn("LDA TABLE,X", out)
        self.assertNotIn("LDA TABLE,X,", out)

    def test_non_6502_mnemonic_is_commented(self):
        src = "HRRZ 14,.JBDDT##\n"
        out = Translator().translate(src).text
        self.assertIn("; HRRZ 14,.JBDDT##", out)

    def test_unresolved_if_expression_falls_back_to_false(self):
        src = "IF BUF,<LDAI 1>\n"
        out = Translator().translate(src).text
        self.assertIn(".if 0 ; unresolved .if expression for ca65:", out)

    def test_parenthesized_immediate_uses_low_byte(self):
        src = "CPX #(TEMPST+STRSIZ)*NUMTMP\n"
        out = Translator().translate(src).text
        self.assertIn("CPX #<((TEMPST+STRSIZ)*NUMTMP)", out)

    def test_cli_strict_returns_nonzero_on_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "warn.asm"
            src.write_text('IRPC Q,<IFDIF <Q><\">,<EXP \"Q\">>>\n', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["--in", str(src), "--dry-run", "--strict"])
            self.assertEqual(1, rc)

    def test_cli_strict_returns_zero_without_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "ok.asm"
            src.write_text('DCI"END"\n', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = main(["--in", str(src), "--dry-run", "--strict"])
            self.assertEqual(0, rc)
