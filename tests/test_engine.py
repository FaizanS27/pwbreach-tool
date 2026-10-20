"""
Offline tests for the verdict logic. The HIBP network call is mocked so the
tests run without internet. They use the small demo data in data/.

Run from the repository root:
    python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import engine  # noqa: E402


class VerdictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dictionary = engine.load_dictionary(engine.DEMO_DICT)

    def check(self, password, hibp_count=0):
        with patch("engine.check_password_baseline", return_value=hibp_count):
            return engine.full_check(password, self.dictionary)

    def test_entropy_of_empty_and_repeated(self):
        self.assertEqual(engine.shannon_entropy(""), 0.0)
        self.assertEqual(engine.shannon_entropy("aaaa"), 0.0)

    def test_breach_outranks_everything(self):
        r = self.check("xK9#mPq2$vLw8zRt", hibp_count=1234)
        self.assertEqual(r["verdict"], "COMPROMISED")

    def test_dictionary_hit_is_common_password(self):
        r = self.check("letmein")
        self.assertEqual(r["verdict"], "WEAK - COMMON PASSWORD")

    def test_bloom_filter_hit_is_common_password(self):
        r = self.check("Tr0ub4dor-demo-9271")
        self.assertEqual(r["verdict"], "WEAK - COMMON PASSWORD")

    def test_guessable_pattern(self):
        r = self.check("qwertyuiop")
        self.assertEqual(r["verdict"], "WEAK - PREDICTABLE PATTERN")

    def test_strong(self):
        r = self.check("xK9#mPq2$vLw8zRt")
        self.assertEqual(r["verdict"], "STRONG")

    def test_bloom_filter_has_no_false_negatives(self):
        path = os.path.join(engine.BASE_DIR, "data", "sample_breach_list.txt")
        with open(path, encoding="utf-8") as f:
            for line in f:
                pw = line.strip()
                if pw:
                    self.assertTrue(engine.in_breach_compilation(pw), pw)


class ApiTests(unittest.TestCase):
    def test_api_returns_verdict_and_rejects_empty(self):
        import app as app_module
        client = app_module.app.test_client()
        with patch("engine.check_password_baseline", return_value=0):
            ok = client.post("/api/check", json={"password": "letmein"})
            bad = client.post("/api/check", json={})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.get_json()["verdict"], "WEAK - COMMON PASSWORD")
        self.assertEqual(bad.status_code, 400)


if __name__ == "__main__":
    unittest.main()
