"""AttackEngine 单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_offense.attack_engine.engine import AttackEngine


class TestAttackEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AttackEngine("http://example.com")

    def test_engine_init(self):
        self.assertEqual(self.engine.target_url, "http://example.com")
        self.assertEqual(len(self.engine.findings), 0)

    def test_engine_init_strips_trailing_slash(self):
        engine = AttackEngine("http://example.com/")
        self.assertEqual(engine.target_url, "http://example.com")

    def test_engine_detectors_registered(self):
        expected = ["xss", "sqli", "ssti", "lfi", "ssrf", "xxe", "rce", "nosqli", "infoleak"]
        for mod in expected:
            self.assertIn(mod, self.engine._detectors)

    def test_engine_findings_empty_initially(self):
        self.assertEqual(self.engine.findings, [])

    def test_engine_get_findings_json(self):
        result = self.engine.get_findings_json()
        self.assertIn("target", result)
        self.assertIn("findings", result)
        self.assertIn("total", result)
        self.assertEqual(result["total"], 0)

    @patch("secops_offense.attack_engine.engine.http_get")
    def test_engine_run_all_unauthorized(self, mock_get):
        with patch("secops_offense.attack_engine.engine.check_auth", return_value=False):
            result = self.engine.run_all(modules=["xss"])
            self.assertEqual(result, [])

    def test_engine_report_no_findings(self):
        from datetime import datetime
        self.engine.start_time = datetime.now()
        self.engine.end_time = datetime.now()
        self.engine.report()


if __name__ == "__main__":
    unittest.main()
