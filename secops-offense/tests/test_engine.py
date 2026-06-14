import unittest
import tempfile
import json
import os
from datetime import datetime
from unittest.mock import patch, MagicMock
from secops_offense.attack_engine.engine import AttackEngine, start_attack
from secops_offense.attack_engine.finding import Finding


class TestAttackEngineInit(unittest.TestCase):
    def test_basic_init(self):
        engine = AttackEngine("http://target.com")
        self.assertEqual(engine.target_url, "http://target.com")
        self.assertEqual(engine.findings, [])
        self.assertIsNone(engine.start_time)
        self.assertIsNone(engine.end_time)

    def test_strips_trailing_slash(self):
        engine = AttackEngine("http://target.com/")
        self.assertEqual(engine.target_url, "http://target.com")

    def test_all_17_detectors_registered(self):
        engine = AttackEngine("http://target.com")
        expected = [
            "xss", "sqli", "ssti", "lfi", "ssrf", "xxe", "rce",
            "nosqli", "infoleak", "jwt", "idor", "cors", "redirect",
            "crlf", "deserialization", "ldap", "subdomain_takeover"
        ]
        for mod in expected:
            self.assertIn(mod, engine._detectors, f"{mod} not registered")
        self.assertEqual(len(engine._detectors), 17)


class TestAuthorize(unittest.TestCase):
    @patch("secops_offense.attack_engine.engine.request_authorization", return_value=True)
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=False)
    def test_authorize_prompts(self, mock_check, mock_request):
        engine = AttackEngine("http://target.com")
        result = engine.authorize()
        self.assertTrue(result)
        mock_request.assert_called_once_with("http://target.com")

    @patch("secops_offense.attack_engine.engine.check_auth", return_value=True)
    def test_authorize_already_authorized(self, mock_check):
        engine = AttackEngine("http://target.com")
        result = engine.authorize()
        self.assertTrue(result)

    @patch("secops_offense.attack_engine.engine.request_authorization", return_value=False)
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=False)
    def test_authorize_denied(self, mock_check, mock_request):
        engine = AttackEngine("http://target.com")
        result = engine.authorize()
        self.assertFalse(result)


class TestDetectSpa(unittest.TestCase):
    @patch("secops_offense.attack_engine.engine.http_get")
    def test_spa_detected(self, mock_get):
        mock_get.return_value = (200, {}, "<html>SPA app</html>" * 10)
        mock_get.return_value = (200, {}, "<html>SPA app</html>" * 10)
        engine = AttackEngine("http://spa-target.com")
        engine._detect_spa()
        self.assertIsInstance(engine._is_spa, bool)

    @patch("secops_offense.attack_engine.engine.http_get")
    def test_not_spa(self, mock_get):
        mock_get.side_effect = [
            (200, {}, "a" * 1000),
            (200, {}, "404 not found"),
        ]
        engine = AttackEngine("http://regular.com")
        engine._detect_spa()
        self.assertFalse(engine._is_spa)


class TestRunAll(unittest.TestCase):
    def test_unauthorized_returns_empty(self):
        with patch("secops_offense.attack_engine.engine.check_auth", return_value=False):
            engine = AttackEngine("http://target.com")
            result = engine.run_all(modules=["xss"])
            self.assertEqual(result, [])

    @patch("secops_offense.attack_engine.engine.http_get", return_value=(200, {}, "ok"))
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=True)
    def test_run_single_module(self, mock_auth, mock_get):
        engine = AttackEngine("http://target.com")
        with patch.object(engine, "_detect_spa"), \
             patch.object(engine._detectors["xss"], "test", return_value=[]):
            result = engine.run_all(modules=["xss"])
        self.assertIsInstance(result, list)
        self.assertIsNotNone(engine.start_time)
        self.assertIsNotNone(engine.end_time)

    @patch("secops_offense.attack_engine.engine.http_get", return_value=(200, {}, "ok"))
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=True)
    def test_run_unknown_module_skipped(self, mock_auth, mock_get):
        engine = AttackEngine("http://target.com")
        with patch.object(engine, "_detect_spa"):
            result = engine.run_all(modules=["nonexistent"])
        self.assertEqual(result, [])

    @patch("secops_offense.attack_engine.engine.http_get", return_value=(200, {}, "ok"))
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=True)
    def test_run_with_findings(self, mock_auth, mock_get):
        finding = Finding("xss", "high", "XSS Found", "http://target.com/page", payload="<script>")
        engine = AttackEngine("http://target.com")
        with patch.object(engine, "_detect_spa"), \
             patch.object(engine._detectors["xss"], "test", return_value=[finding]):
            result = engine.run_all(modules=["xss"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].severity, "high")

    @patch("secops_offense.attack_engine.engine.http_get", return_value=(200, {}, "ok"))
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=True)
    def test_run_module_exception(self, mock_auth, mock_get):
        engine = AttackEngine("http://target.com")
        with patch.object(engine, "_detect_spa"), \
             patch.object(engine._detectors["xss"], "test", side_effect=Exception("boom")):
            result = engine.run_all(modules=["xss"])
        self.assertEqual(result, [])


class TestReport(unittest.TestCase):
    def test_report_no_findings(self):
        engine = AttackEngine("http://target.com")
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        engine.report()

    def test_report_with_findings(self):
        engine = AttackEngine("http://target.com")
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        engine.findings = [
            Finding("xss", "high", "XSS", "http://target.com/page", payload="<script>alert(1)</script>"),
            Finding("sqli", "critical", "SQLi", "http://target.com/api", payload="' OR 1=1--"),
        ]
        engine.report()


class TestGetFindingsJson(unittest.TestCase):
    def test_empty(self):
        engine = AttackEngine("http://target.com")
        result = engine.get_findings_json()
        self.assertEqual(result["target"], "http://target.com")
        self.assertEqual(result["total"], 0)
        self.assertIn("timestamp", result)
        self.assertIn("findings", result)
        self.assertIn("audit_log_count", result)

    def test_with_findings(self):
        engine = AttackEngine("http://target.com")
        engine.findings = [
            Finding("xss", "high", "XSS", "http://target.com/page"),
        ]
        result = engine.get_findings_json()
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["findings"][0]["vuln_type"], "xss")


class TestSaveReport(unittest.TestCase):
    def test_save_creates_files(self):
        engine = AttackEngine("http://target.com")
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path, md_path = engine.save_report(output_dir=tmpdir)
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(md_path))
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "http://target.com")

    def test_save_with_findings(self):
        engine = AttackEngine("http://target.com")
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        engine.findings = [
            Finding("sqli", "critical", "SQLi", "http://target.com/api", payload="' OR 1=1--"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path, md_path = engine.save_report(output_dir=tmpdir)
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["total"], 1)


class TestGenerateMarkdownReport(unittest.TestCase):
    def test_empty_findings(self):
        engine = AttackEngine("http://target.com")
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        md = engine._generate_markdown_report()
        self.assertIn("http://target.com", md)
        self.assertIn("0 个漏洞", md)

    def test_with_findings(self):
        engine = AttackEngine("http://target.com")
        engine.start_time = datetime.now()
        engine.end_time = datetime.now()
        engine.findings = [
            Finding("xss", "high", "XSS Vuln", "http://target.com/page", payload="<script>", evidence="reflected", description="XSS", remediation="encode output"),
        ]
        md = engine._generate_markdown_report()
        self.assertIn("XSS Vuln", md)
        self.assertIn("1 个漏洞", md)
        self.assertIn("script", md)


class TestStartAttack(unittest.TestCase):
    @patch("secops_offense.attack_engine.engine.request_authorization", return_value=False)
    @patch("secops_offense.attack_engine.engine.check_auth", return_value=False)
    def test_denied_returns_none(self, mock_check, mock_request):
        result = start_attack("http://target.com", modules=["xss"])
        self.assertIsNone(result)

    @patch("secops_offense.attack_engine.engine.check_auth", return_value=True)
    def test_adds_http_prefix(self, mock_auth):
        with patch.object(AttackEngine, "report"), \
             patch.object(AttackEngine, "save_report", return_value=("a", "b")), \
             patch.object(AttackEngine, "run_all", return_value=[]):
            result = start_attack("target.com", modules=["xss"])
        self.assertIsNotNone(result)
        self.assertTrue(result.target_url.startswith("http"))


if __name__ == "__main__":
    unittest.main()
