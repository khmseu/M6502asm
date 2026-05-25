import re
import unittest

from m6502_to_xa65 import Translator


class TranslateTests(unittest.TestCase):
    def test_simple_instruction_conversion(self):
        src = "LDAI 42\nLDADY PTR\nJMPD TARGET\n"
        out = Translator().translate(src).text
        self.assertIn("LDA #42", out)
        self.assertIn("LDA (PTR),Y", out)
        self.assertIn("JMP (TARGET)", out)

    def test_directive_conversion(self):
        src = "ORG ^O20000\nFOO==1\nBAR=2\n"
        out = Translator().translate(src).text
        self.assertIn(".org ^O20000", out)
        self.assertIn("FOO .equ 1", out)
        self.assertIn("BAR .equ 2", out)

    def test_label_and_comment_preservation(self):
        src = "START:: LDAI 0 ; init\n"
        out = Translator().translate(src).text
        self.assertIn("START: LDA #0 ; init", out)

    def test_macro_conversion(self):
        src = "DEFINE CLR(WD),<\n\tLDAI\t0\n\tSTA\tWD>\n"
        out = Translator().translate(src).text
        self.assertIn(".macro CLR WD", out)
        self.assertIn("LDA #0", out)
        self.assertRegex(out, r"STA\s+WD")
        self.assertIn(".endmacro", out)

    def test_include_handling(self):
        src = "SEARCH M6502\n"
        out = Translator(preserve_includes=True).translate(src).text
        self.assertIn('.include "M6502"', out)

    def test_dci_conversion(self):
        src = 'DCI"END"\n'
        out = Translator().translate(src).text
        self.assertIn(".byte 'E', 'N', 'D'|$80", out)

    def test_define_with_irpc_quote_pattern(self):
        src = (
            "DEFINE\tDT(Q),<\n"
            "IRPC\tQ,<IFDIF <Q><\">,<EXP \"Q\">>>\n"
            "DEFINE\tLDWD\t(WD),<\n"
            "\tLDA\tWD\n"
            "\tLDY\t<WD>+1>\n"
        )
        result = Translator().translate(src)
        self.assertEqual([], result.warnings)
        self.assertIn(".macro DT Q", result.text)
        self.assertIn(".byte Q", result.text)
        self.assertIn(".macro LDWD WD", result.text)

    def test_comment_block_is_preserved_as_comments(self):
        src = "COMMENT *\nHELLO\nWORLD\n*\nLDAI 1\n"
        out = Translator().translate(src).text
        self.assertIn("; COMMENT *", out)
        self.assertIn("; HELLO", out)
        self.assertIn("; WORLD", out)
        self.assertIn("; *", out)
        self.assertIn("LDA #1", out)

    def test_metadata_directives_do_not_emit_warnings(self):
        src = "TITLE ABC\nSUBTTL DEF\nPAGE\nSALL\nRADIX 10\nPRINTX FOO\n"
        result = Translator().translate(src)
        self.assertEqual([], result.warnings)
        self.assertIn("; TITLE ABC", result.text)

    def test_exp_and_end_conversion(self):
        src = "EXP ^O15\nEND $Z+START\n"
        out = Translator().translate(src).text
        self.assertIn(".byte ^O15", out)
        self.assertIn(".end $Z+START", out)

    def test_trailing_endif_closer_on_data(self):
        src = "0>\n"
        out = Translator().translate(src).text
        self.assertIn(".byte 0", out)
        self.assertIn(".endif", out)


if __name__ == "__main__":
    unittest.main()
