"""firewall 模块单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_defense import firewall


class TestFirewall(unittest.TestCase):

    def test_fallback_ips_not_empty(self):
        self.assertGreater(len(firewall.FALLBACK_IPS), 0)

    def test_fallback_ips_format(self):
        import re
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        for ip in firewall.FALLBACK_IPS:
            self.assertRegex(ip, ip_pattern)

    @patch("secops_core.utils.is_windows", return_value=False)
    @patch("secops_core.utils.run_cmd")
    def test_update_linux_nftables_no_nft(self, mock_run, mock_windows):
        mock_run.return_value = (1, "", "nft not found")
        result = firewall.update_linux_nftables(["1.2.3.4"])
        self.assertFalse(result)

    @patch("secops_core.utils.is_windows", return_value=True)
    @patch("secops_core.utils.run_ps_cmd")
    def test_update_windows_firewall(self, mock_ps, mock_windows):
        mock_ps.return_value = (0, "", "")
        result = firewall.update_windows_firewall_rules(["1.2.3.4", "5.6.7.8"])
        self.assertTrue(result)
        self.assertEqual(mock_ps.call_count, 2)


if __name__ == "__main__":
    unittest.main()
