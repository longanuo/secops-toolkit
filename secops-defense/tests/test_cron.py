"""cron 模块单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_defense import cron


class TestCron(unittest.TestCase):

    @patch("secops_core.utils.is_windows", return_value=True)
    def test_setup_cronjob_windows(self, mock_windows):
        result = cron.setup_cronjob()
        self.assertFalse(result)

    @patch("secops_core.utils.is_windows", return_value=False)
    @patch("secops_core.utils.is_admin", return_value=False)
    def test_setup_cronjob_no_admin(self, mock_admin, mock_windows):
        result = cron.setup_cronjob()
        self.assertFalse(result)

    @patch("secops_core.utils.is_windows", return_value=True)
    def test_run_cron_check_windows(self, mock_windows):
        with patch.object(cron, "evaluator") as mock_eval:
            mock_eval.run_evaluation.return_value = {"score": 80, "timestamp": "2024-01-01", "load": {"hostname": "test"}}
            cron.run_cron_check()

    def test_send_webhook_alert_no_url(self):
        cron.send_webhook_alert(None, 50, {"load": {"hostname": "test"}, "timestamp": "2024-01-01", "ssh": {"issues": []}})

    @patch("secops_core.utils.is_windows", return_value=True)
    def test_get_webhook_url_from_env(self, mock_windows):
        with patch("os.environ", {"SECOPS_WEBHOOK_URL": "http://test.com"}):
            url = cron.get_webhook_url()
            self.assertEqual(url, "http://test.com")


if __name__ == "__main__":
    unittest.main()
