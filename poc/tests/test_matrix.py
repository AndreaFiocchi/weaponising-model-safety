import unittest

from engine.handlers import DOS_BASELINE, HANDLERS, REFERENCE_FIX
from engine.landings import Category, Landing
from engine.states import NON_VERDICT, ClassifierState as S
from matrix.run import run_matrix, summarize


class MatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = run_matrix()

    def test_controls_land_safe_for_every_handler(self):
        for hid, row in self.matrix.items():
            with self.subTest(hid):
                self.assertIs(row[S.VERDICT_MALICIOUS].landing, Landing.DETECTED)
                self.assertIs(row[S.VERDICT_BENIGN].landing, Landing.CORRECT_ACCEPT)

    def test_reference_fix_holds_every_non_verdict(self):
        row = self.matrix[REFERENCE_FIX.ID]
        for state in NON_VERDICT:
            with self.subTest(state.code):
                self.assertIs(row[state].landing, Landing.HELD_FOR_HUMAN)

    def test_dos_baseline_halts_and_never_steers(self):
        row = self.matrix[DOS_BASELINE.ID]
        for state in NON_VERDICT:
            with self.subTest(state.code):
                self.assertIs(row[state].landing.category, Category.DOS)

    def test_every_vulnerable_handler_flips_a_detected_item(self):
        for handler in HANDLERS:
            if handler in (DOS_BASELINE, REFERENCE_FIX):
                continue
            with self.subTest(handler.ID):
                self.assertTrue(summarize(self.matrix[handler.ID])["flips"])


if __name__ == "__main__":
    unittest.main()
