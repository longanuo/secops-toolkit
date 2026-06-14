"""威胁情报模块单元测试"""
import unittest
from unittest.mock import patch, MagicMock
from secops_defense.threat_intel import (
    _get_reputation,
    get_threat_summary,
    THREAT_INTEL_SOURCES
)


class TestThreatIntel(unittest.TestCase):

    def test_threat_sources_not_empty(self):
        self.assertGreater(len(THREAT_INTEL_SOURCES), 0)

    def test_threat_sources_has_ipsum(self):
        self.assertIn("ipsum", THREAT_INTEL_SOURCES)

    def test_get_reputation_critical(self):
        result = _get_reputation(10)
        self.assertEqual(result, "critical")

    def test_get_reputation_high(self):
        result = _get_reputation(6)
        self.assertEqual(result, "high")

    def test_get_reputation_medium(self):
        result = _get_reputation(4)
        self.assertEqual(result, "medium")

    def test_get_reputation_low(self):
        result = _get_reputation(1)
        self.assertEqual(result, "low")

    @patch('secops_defense.threat_intel.load_local_threat_intel', return_value=[])
    def test_get_threat_summary_empty(self, mock_load):
        summary = get_threat_summary()
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["critical"], 0)

    @patch('secops_defense.threat_intel.load_local_threat_intel')
    def test_get_threat_summary_with_data(self, mock_load):
        mock_load.return_value = [
            {"reputation": "critical"},
            {"reputation": "high"},
            {"reputation": "medium"},
            {"reputation": "low"},
        ]
        summary = get_threat_summary()
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 1)


if __name__ == "__main__":
    unittest.main()
