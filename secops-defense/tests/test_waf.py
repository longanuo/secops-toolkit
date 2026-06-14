"""WAF 模块单元测试"""
import unittest
from secops_defense.waf import detect_waf, get_bypass_payloads, WAF_FINGERPRINTS


class TestWAF(unittest.TestCase):

    def test_waf_fingerprints_not_empty(self):
        self.assertGreater(len(WAF_FINGERPRINTS), 0)

    def test_waf_fingerprints_has_cloudflare(self):
        self.assertIn("Cloudflare", WAF_FINGERPRINTS)

    def test_waf_fingerprints_has_alibaba(self):
        self.assertIn("阿里云 WAF", WAF_FINGERPRINTS)

    def test_get_bypass_payloads_xss(self):
        payloads = get_bypass_payloads("Cloudflare", "XSS")
        self.assertGreater(len(payloads), 0)

    def test_get_bypass_payloads_sqli(self):
        payloads = get_bypass_payloads("ModSecurity", "SQLi")
        self.assertGreater(len(payloads), 0)

    def test_get_bypass_payloads_unknown_waf(self):
        payloads = get_bypass_payloads("UnknownWAF", "XSS")
        self.assertGreater(len(payloads), 0)


if __name__ == "__main__":
    unittest.main()
