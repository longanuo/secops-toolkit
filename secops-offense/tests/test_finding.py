"""Finding 数据结构单元测试"""
import unittest
from secops_offense.attack_engine.finding import Finding


class TestFinding(unittest.TestCase):

    def setUp(self):
        self.finding = Finding(
            vuln_type="XSS",
            severity="high",
            title="反射型 XSS",
            location="http://example.com?q=test",
            payload="<script>alert(1)</script>",
            evidence="Payload 出现在响应中",
            description="参数 q 存在 XSS 漏洞",
            remediation="对用户输入进行编码"
        )

    def test_finding_attributes(self):
        self.assertEqual(self.finding.vuln_type, "XSS")
        self.assertEqual(self.finding.severity, "high")
        self.assertEqual(self.finding.title, "反射型 XSS")

    def test_finding_to_dict(self):
        d = self.finding.to_dict()
        self.assertIn("vuln_type", d)
        self.assertIn("severity", d)
        self.assertIn("title", d)
        self.assertIn("location", d)
        self.assertIn("payload", d)
        self.assertIn("timestamp", d)

    def test_finding_str(self):
        s = str(self.finding)
        self.assertIn("XSS", s)
        self.assertIn("HIGH", s)

    def test_finding_timestamp(self):
        self.assertIsNotNone(self.finding.timestamp)

    def test_finding_payload_truncation(self):
        long_payload = "A" * 300
        finding = Finding("XSS", "high", "test", "loc", payload=long_payload)
        d = finding.to_dict()
        self.assertLessEqual(len(d["payload"]), 200)


if __name__ == "__main__":
    unittest.main()
