"""utils 模块单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_core import utils


class TestUtils(unittest.TestCase):

    def test_is_windows_returns_bool(self):
        result = utils.is_windows()
        self.assertIsInstance(result, bool)

    def test_is_admin_returns_bool(self):
        result = utils.is_admin()
        self.assertIsInstance(result, bool)

    @patch("platform.system", return_value="Windows")
    def test_is_windows_true(self, mock_system):
        self.assertTrue(utils.is_windows())

    @patch("platform.system", return_value="Linux")
    def test_is_windows_false(self, mock_system):
        self.assertFalse(utils.is_windows())

    @patch("subprocess.run")
    def test_run_cmd_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")
        rc, stdout, stderr = utils.run_cmd(["echo", "hello"])
        self.assertEqual(rc, 0)
        self.assertEqual(stdout, "output")

    @patch("subprocess.run")
    def test_run_cmd_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        rc, stdout, stderr = utils.run_cmd(["false"])
        self.assertEqual(rc, 1)
        self.assertEqual(stderr, "error")


if __name__ == "__main__":
    unittest.main()
