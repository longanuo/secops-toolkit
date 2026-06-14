"""异常检测模块单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_defense.anomaly import (
    check_failed_logins,
    check_suspicious_processes,
    check_unauthorized_keys,
    run_anomaly_detection
)


class TestAnomalyDetection(unittest.TestCase):

    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd')
    def test_check_failed_logins_windows(self, mock_run, mock_windows):
        mock_run.return_value = (0, "", "")
        result = check_failed_logins()
        self.assertIsInstance(result, list)

    @patch('secops_core.utils.is_windows', return_value=False)
    @patch('os.path.exists', return_value=False)
    def test_check_failed_logins_no_log(self, mock_exists, mock_windows):
        result = check_failed_logins()
        self.assertEqual(result, [])

    @patch('secops_core.utils.is_windows', return_value=True)
    @patch('secops_core.utils.run_cmd')
    def test_check_suspicious_processes_windows(self, mock_run, mock_windows):
        mock_run.return_value = (0, "", "")
        result = check_suspicious_processes()
        self.assertIsInstance(result, list)

    @patch('secops_core.utils.is_windows', return_value=True)
    def test_check_unauthorized_keys_windows(self, mock_windows):
        result = check_unauthorized_keys()
        self.assertEqual(result, [])

    @patch('secops_defense.anomaly.check_failed_logins', return_value=[])
    @patch('secops_defense.anomaly.check_suspicious_processes', return_value=[])
    @patch('secops_defense.anomaly.check_unauthorized_keys', return_value=[])
    def test_run_anomaly_detection(self, mock_keys, mock_proc, mock_logins):
        result = run_anomaly_detection()
        self.assertIsInstance(result, list)


if __name__ == "__main__":
    unittest.main()
