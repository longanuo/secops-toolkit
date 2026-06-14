import unittest
from unittest.mock import patch
from secops_core import utils

class TestUtils(unittest.TestCase):
    @patch('platform.system')
    def test_is_windows(self, mock_system):
        mock_system.return_value = "Windows"
        self.assertTrue(utils.is_windows())

        mock_system.return_value = "Linux"
        self.assertFalse(utils.is_windows())

    @patch('subprocess.run')
    def test_run_cmd(self, mock_subprocess_run):
        class MockResult:
            returncode = 0
            stdout = "success"
            stderr = ""
        mock_subprocess_run.return_value = MockResult()
        
        rc, out, err = utils.run_cmd(["echo", "test"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "success")

if __name__ == '__main__':
    unittest.main()
