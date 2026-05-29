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

    def test_include_handling(self):
        src = "SEARCH M6502\n"
        out = Translator(preserve_includes=True).translate(src).text
        self.assertIn('.include "M6502"', out)

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
