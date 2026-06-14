"""hardener 模块单元测试"""
import unittest
from unittest.mock import patch, MagicMock, mock_open
from secops_defense import hardener


class TestHardener(unittest.TestCase):

    def test_backup_file_not_exists(self):
        with patch("os.path.exists", return_value=False):
            ok, msg = hardener.backup_file("/nonexistent/file")
            self.assertFalse(ok)

    def test_backup_file_exists(self):
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="test content")), \
             patch.object(hardener, "BACKUP_REGISTRY", []):
            ok, backup_path = hardener.backup_file("/etc/passwd")
            self.assertTrue(ok)
            self.assertIn("bak_", backup_path)

    def test_backup_registry_updated(self):
        hardener.BACKUP_REGISTRY.clear()
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data="content")):
            hardener.backup_file("/test/file")
            self.assertEqual(len(hardener.BACKUP_REGISTRY), 1)

    @patch("os.path.exists", return_value=False)
    def test_harden_ssh_no_config(self, mock_exists):
        ok, msg = hardener.harden_ssh()
        self.assertFalse(ok)
        self.assertIn("未找到", msg)

    @patch("secops_core.utils.is_windows", return_value=True)
    def test_run_hardening_calls_windows(self, mock_windows):
        with patch.object(hardener, "run_windows_hardening", return_value=True) as mock_win:
            result = hardener.run_hardening()
            mock_win.assert_called_once()

    def test_harden_password_policy(self):
        with patch("os.makedirs"), \
             patch("builtins.open", mock_open()) as mock_file:
            ok, msg = hardener.harden_password_policy()
            self.assertTrue(ok)
            self.assertIn("12位", msg)


if __name__ == "__main__":
    unittest.main()
