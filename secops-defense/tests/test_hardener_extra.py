import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock
from secops_defense import hardener


class TestBackupFile(unittest.TestCase):
    def test_backup_existing_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content")
            f.flush()
            path = f.name
        try:
            ok, backup_path = hardener.backup_file(path)
            self.assertTrue(ok)
            self.assertTrue(os.path.exists(backup_path))
            with open(backup_path, "r") as f:
                self.assertEqual(f.read(), "test content")
            os.unlink(backup_path)
        finally:
            os.unlink(path)

    def test_backup_nonexistent_file(self):
        ok, msg = hardener.backup_file("/nonexistent/file.txt")
        self.assertFalse(ok)
        self.assertEqual(msg, "文件不存在")


class TestHardenSsh(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=False)
    def test_no_config_file(self, __, _):
        ok, msg = hardener.harden_ssh()
        self.assertFalse(ok)
        self.assertIn("未找到", msg)


class TestHardenPasswordPolicy(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd', return_value=(0, "success", ""))
    def test_windows(self, mock_cmd, _):
        ok, msg = hardener.harden_password_policy()
        self.assertTrue(ok)

    @patch('secops_core.utils.is_windows', return_value=False)
    def test_linux(self, _):
        ok, msg = hardener.harden_password_policy()
        self.assertTrue(ok)


class TestRunHardening(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.is_admin', return_value=True)
    @patch('secops_defense.hardener.harden_password_policy', return_value=(True, "ok"))
    @patch('secops_defense.hardener.backup_file', return_value=(True, "ok"))
    def test_windows_calls(self, mock_backup, mock_pwd, mock_admin, mock_win):
        result = hardener.run_hardening()
        self.assertTrue(result)

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('secops_core.utils.is_admin', return_value=True)
    @patch('secops_defense.hardener.harden_ssh', return_value=(True, "ok"))
    @patch('secops_defense.hardener.harden_password_policy', return_value=(True, "ok"))
    def test_linux_calls(self, mock_pwd, mock_ssh, mock_admin, mock_win):
        with patch('os.path.exists', return_value=False):
            result = hardener.run_hardening()
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
