"""config 模块单元测试"""
import unittest
from unittest.mock import patch
from pathlib import Path
from secops_core import config


class TestConfig(unittest.TestCase):

    def test_cache_dir_exists(self):
        self.assertIsInstance(config.CACHE_DIR, Path)

    def test_log_dir_exists(self):
        self.assertIsInstance(config.LOG_DIR, Path)

    def test_report_dir_exists(self):
        self.assertIsInstance(config.REPORT_DIR, Path)

    def test_github_raw_base(self):
        self.assertEqual(config.GITHUB_RAW_BASE, "https://raw.githubusercontent.com")

    def test_http_timeout_positive(self):
        self.assertGreater(config.HTTP_TIMEOUT, 0)

    def test_attack_delay_positive(self):
        self.assertGreater(config.ATTACK_DELAY, 0)

    @patch.dict("os.environ", {"SECOPS_CACHE_DIR": "/tmp/test_cache"})
    def test_cache_dir_from_env(self):
        import importlib
        importlib.reload(config)
        self.assertIn("test_cache", str(config.CACHE_DIR))
        importlib.reload(config)

    def test_ensure_dirs_creates_directories(self):
        with patch("pathlib.Path.mkdir") as mock_mkdir:
            config.ensure_dirs()
            self.assertEqual(mock_mkdir.call_count, 3)


if __name__ == "__main__":
    unittest.main()
