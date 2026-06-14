import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock
from secops_defense import reporter


def _make_scan_data(score=85):
    return {
        "timestamp": "2026-01-01 12:00:00",
        "score": score,
        "load": {
            "hostname": "test-host",
            "os_type": "Windows",
            "os_release": "Windows-10",
            "cpu_cores": 8,
            "memory_total": "16.0 GB",
            "memory_used_percent": "50.0%",
            "disk_total": "500.0 GB",
            "disk_used_percent": "60.0%",
        },
        "accounts": {
            "uid_zero_users": ["root"],
            "user_count": 10,
            "status": "pass",
            "description": "OK",
        },
        "ssh": {
            "ssh_installed": False,
            "permit_root_login": "n/a",
            "password_authentication": "n/a",
            "ssh_port": "n/a",
            "status": "n/a",
            "issues": [],
        },
        "services": {"windows_firewall": "active"},
        "ports": ["80", "443"],
    }


class TestGetBasePath(unittest.TestCase):
    def test_returns_path(self):
        path = reporter.get_base_path()
        self.assertIsInstance(path, str)
        self.assertTrue(len(path) > 0)


class TestGenerateReports(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    def test_generates_files(self, _):
        scan_data = _make_scan_data(85)
        orig_dir = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            try:
                html_path, md_path = reporter.generate_reports(scan_data)
                self.assertTrue(os.path.exists(html_path))
                self.assertTrue(os.path.exists(md_path))
                with open(md_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertIn("test-host", content)
                self.assertIn("85", content)
            finally:
                os.chdir(orig_dir)

    @patch('secops_core.utils.is_windows', return_value=True)
    def test_score_classes(self, _):
        orig_dir = os.getcwd()
        for score, expected_class in [(90, "score-high"), (70, "score-med"), (40, "score-low")]:
            scan_data = _make_scan_data(score)
            with tempfile.TemporaryDirectory() as tmpdir:
                os.chdir(tmpdir)
                try:
                    html_path, md_path = reporter.generate_reports(scan_data)
                    with open(html_path, "r", encoding="utf-8") as f:
                        html = f.read()
                    self.assertIn(expected_class, html)
                finally:
                    os.chdir(orig_dir)


if __name__ == "__main__":
    unittest.main()
