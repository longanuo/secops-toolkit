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

    @patch('secops_core.utils.is_windows')
    @patch('secops_core.utils.run_cmd')
    @patch('secops_core.utils.run_ps_cmd')
    def test_check_windows_policy(self, mock_run_ps_cmd, mock_run_cmd, mock_is_windows):
        mock_is_windows.return_value = True
        
        # 1. 模拟 net user Guest 的输出（包含 Yes，表示未禁用）
        # 2. 模拟 net accounts 的输出（包含 Minimum password length: 7）
        # 3. 模拟 Get-ItemProperty 的输出（包含 UserAuthentication : 0，表示未启用 NLA）
        mock_run_cmd.side_effect = [
            (0, "Account active               Yes\n", ""),
            (0, "Minimum password length:       7\n", "")
        ]
        mock_run_ps_cmd.return_value = (0, "UserAuthentication : 0\n", "")
        
        res = evaluator.check_windows_policy()
        self.assertEqual(res["guest_disabled"], "no")
        self.assertEqual(res["min_password_len"], 7)
        self.assertEqual(res["rdp_nla_enabled"], "no")
        self.assertEqual(res["status"], "warning")
        self.assertTrue(len(res["issues"]) >= 3)

    @patch('secops_core.utils.is_windows')
    @patch('os.path.exists')
    @patch('os.stat')
    def test_check_linux_files(self, mock_stat, mock_exists, mock_is_windows):
        mock_is_windows.return_value = False
        mock_exists.return_value = True
        
        # 模拟文件属性权限
        class MockStat:
            st_mode = 0o100777 # 777权限，过高
        mock_stat.return_value = MockStat()
        
        res = evaluator.check_linux_files()
        self.assertEqual(res["status"], "warning")
        self.assertIn("/etc/passwd", res["file_permissions"])
        self.assertTrue(any("权限过高" in iss for iss in res["issues"]))

if __name__ == '__main__':
    unittest.main()
