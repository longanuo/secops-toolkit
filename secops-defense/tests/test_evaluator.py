import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock, mock_open
from secops_defense import evaluator


class TestGetSystemLoad(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    def test_windows_returns_dict(self, _):
        load = evaluator.get_system_load()
        self.assertIsInstance(load, dict)
        self.assertIn("hostname", load)
        self.assertIn("os_type", load)
        self.assertIn("cpu_cores", load)
        self.assertIn("memory_total", load)
        self.assertIn("memory_used_percent", load)
        self.assertIn("disk_total", load)
        self.assertIn("disk_used_percent", load)

    @patch('secops_core.utils.is_windows', return_value=False)
    def test_linux_returns_dict(self, _):
        load = evaluator.get_system_load()
        self.assertIn("GB", load["memory_total"])
        self.assertIn("%", load["memory_used_percent"])


class TestCheckAccounts(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd', return_value=(0, "User accounts\n------\nAdministrator\nGuest\n", ""))
    def test_windows_accounts(self, mock_cmd, _):
        result = evaluator.check_accounts()
        self.assertEqual(result["status"], "info")
        self.assertIn("Windows", result["description"])

    @patch('secops_core.utils.is_windows', return_value=False)
    def test_linux_single_root(self, _):
        passwd_content = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        m = mock_open(read_data=passwd_content)
        with patch('builtins.open', m):
            result = evaluator.check_accounts()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["uid_zero_users"], ["root"])

    @patch('secops_core.utils.is_windows', return_value=False)
    def test_linux_multiple_uid_zero(self, _):
        passwd_content = "root:x:0:0:root:/root:/bin/bash\nsuperuser:x:0:0:super:/home/super:/bin/bash\n"
        m = mock_open(read_data=passwd_content)
        with patch('builtins.open', m):
            result = evaluator.check_accounts()
        self.assertEqual(result["status"], "warning")
        self.assertIn("root", result["uid_zero_users"])
        self.assertIn("superuser", result["uid_zero_users"])

    @patch('secops_core.utils.is_windows', return_value=False)
    def test_linux_file_read_error(self, _):
        with patch('builtins.open', side_effect=PermissionError("denied")):
            result = evaluator.check_accounts()
        self.assertIn("失败", result["description"])


class TestCheckSshConfig(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    def test_windows_returns_na(self, _):
        result = evaluator.check_ssh_config()
        self.assertEqual(result["status"], "n/a")

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=False)
    def test_no_sshd_config(self, __, _):
        result = evaluator.check_ssh_config()
        self.assertEqual(result["status"], "warning")
        self.assertIn("未检测到", result["issues"][0])

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=True)
    def test_ssh_default_insecure(self, __, _):
        config = "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n"
        m = mock_open(read_data=config)
        with patch('builtins.open', m):
            result = evaluator.check_ssh_config()
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["permit_root_login"], "yes")
        self.assertEqual(result["password_authentication"], "yes")
        self.assertEqual(result["ssh_port"], "22")
        self.assertEqual(len(result["issues"]), 3)

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=True)
    def test_ssh_hardened(self, __, _):
        config = "PermitRootLogin no\nPasswordAuthentication no\nPort 2222\n"
        m = mock_open(read_data=config)
        with patch('builtins.open', m):
            result = evaluator.check_ssh_config()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["issues"]), 0)

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=True)
    def test_ssh_read_error(self, __, _):
        with patch('builtins.open', side_effect=IOError("fail")):
            result = evaluator.check_ssh_config()
        self.assertTrue(any("失败" in i for i in result["issues"]))


class TestCheckServices(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd', return_value=(0, "ON", ""))
    def test_windows_firewall_active(self, mock_cmd, _):
        result = evaluator.check_services()
        self.assertEqual(result["windows_firewall"], "active")

    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd', return_value=(0, "OFF", ""))
    def test_windows_firewall_inactive(self, mock_cmd, _):
        result = evaluator.check_services()
        self.assertEqual(result["windows_firewall"], "inactive")

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('secops_core.utils.run_cmd')
    def test_linux_services(self, mock_cmd, _):
        mock_cmd.side_effect = [
            (0, "active", ""), (0, "enabled", ""),
            (0, "inactive", ""), (0, "disabled", ""),
            (0, "active", ""), (0, "enabled", ""),
        ]
        result = evaluator.check_services()
        self.assertTrue(result["nftables"]["active"])
        self.assertFalse(result["fail2ban"]["active"])
        self.assertTrue(result["auditd"]["active"])


class TestCheckPorts(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd', return_value=(0, "TCP  0.0.0.0:80  LISTENING  1234\nTCP  0.0.0.0:443  LISTENING  5678\n", ""))
    def test_windows_ports(self, mock_cmd, _):
        result = evaluator.check_ports()
        self.assertIsInstance(result, list)

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('secops_core.utils.run_cmd', return_value=(0, "State  Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\nLISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(\"sshd\",pid=1)\n", ""))
    def test_linux_ss_ports(self, mock_cmd, _):
        result = evaluator.check_ports()
        self.assertIsInstance(result, list)
        self.assertLessEqual(len(result), 50)


class TestCheckWindowsPolicy(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=False)
    def test_linux_returns_na(self, _):
        result = evaluator.check_windows_policy()
        self.assertEqual(result["status"], "n/a")

    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd')
    @patch('secops_core.utils.run_ps_cmd', return_value=(0, "UserAuthentication : 1", ""))
    def test_windows_policy_pass(self, mock_ps, mock_cmd, _):
        mock_cmd.side_effect = [
            (0, "User accounts\n------\nAdministrator\nThe command completed.\nNo", ""),
            (0, "Minimum password length: 14\n", ""),
        ]
        result = evaluator.check_windows_policy()
        self.assertEqual(result["guest_disabled"], "yes")
        self.assertEqual(result["min_password_len"], 14)
        self.assertEqual(result["rdp_nla_enabled"], "yes")

    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd')
    @patch('secops_core.utils.run_ps_cmd', return_value=(0, "UserAuthentication : 0", ""))
    def test_windows_policy_warnings(self, mock_ps, mock_cmd, _):
        mock_cmd.side_effect = [
            (0, "User accounts\n------\nAdministrator\nGuest\nThe command completed.", ""),
            (0, "Minimum password length: 6\n", ""),
        ]
        result = evaluator.check_windows_policy()
        self.assertEqual(result["guest_disabled"], "no")
        self.assertEqual(result["min_password_len"], 6)
        self.assertEqual(result["rdp_nla_enabled"], "no")
        self.assertEqual(result["status"], "warning")
        self.assertTrue(len(result["issues"]) >= 3)


class TestCheckLinuxFiles(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    def test_windows_returns_na(self, _):
        result = evaluator.check_linux_files()
        self.assertEqual(result["status"], "n/a")

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=False)
    def test_no_files(self, __, _):
        result = evaluator.check_linux_files()
        self.assertEqual(result["status"], "pass")


class TestRunEvaluation(unittest.TestCase):
    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd')
    @patch('secops_core.utils.run_ps_cmd', return_value=(0, "UserAuthentication : 1", ""))
    def test_windows_evaluation(self, mock_ps, mock_cmd, _):
        mock_cmd.side_effect = [
            (0, "ON", ""),  # firewall
            (0, "User accounts\n------\nAdministrator\n", ""),  # net user
            (0, "TCP  0.0.0.0:80  LISTENING  1234\n", ""),  # netstat
            (0, "User accounts\n------\nAdministrator\nThe command completed.", ""),  # Guest check
            (0, "Minimum password length: 14\n", ""),  # password len
        ]
        result = evaluator.run_evaluation()
        self.assertIn("score", result)
        self.assertIn("load", result)
        self.assertIn("accounts", result)
        self.assertIn("services", result)
        self.assertIn("ports", result)
        self.assertIn("windows_policy", result)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=False)
    @patch('secops_core.utils.run_cmd')
    def test_linux_evaluation(self, mock_cmd, __, _):
        mock_cmd.side_effect = [
            (0, "root:x:0:0:root:/root:/bin/bash\n", ""),  # accounts
            (0, "State  Recv-Q  Send-Q\nLISTEN  0  128\n", ""),  # ss
            (0, "inactive", ""), (0, "disabled", ""),  # nftables
            (0, "inactive", ""), (0, "disabled", ""),  # fail2ban
            (0, "inactive", ""), (0, "disabled", ""),  # auditd
        ]
        result = evaluator.run_evaluation()
        self.assertIn("score", result)
        self.assertIn("ssh", result)
        self.assertIn("linux_files", result)


if __name__ == '__main__':
    unittest.main()
