"""evaluator 单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_defense import evaluator


class TestEvaluator(unittest.TestCase):
    @patch('secops_core.utils.is_windows')
    def test_get_system_load_windows(self, mock_is_windows):
        mock_is_windows.return_value = True
        load = evaluator.get_system_load()
        self.assertIn("disk_total", load)
        self.assertIn("GB", load["disk_total"])

    @patch('secops_core.utils.is_windows')
    def test_check_ssh_config_linux(self, mock_is_windows):
        mock_is_windows.return_value = False
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = False
            res = evaluator.check_ssh_config()
            self.assertEqual(res["status"], "warning")


if __name__ == '__main__':
    unittest.main()
