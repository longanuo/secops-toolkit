"""检测器模块单元测试"""
import unittest
from secops_offense.attack_engine.modules.xss import XSSDetector
from secops_offense.attack_engine.modules.sqli import SQLiDetector
from secops_offense.attack_engine.modules.ssrf import SSRFDetector
from secops_offense.attack_engine.modules.xxe import XXEDetector
from secops_offense.attack_engine.modules.rce import RCEDetector
from secops_offense.attack_engine.modules.nosqli import NoSQLiDetector
from secops_offense.attack_engine.modules.ssti import SSTIDetector
from secops_offense.attack_engine.modules.lfi import LFIDetector
from secops_offense.attack_engine.modules.infoleak import InfoLeakDetector


class TestDetectorBasics(unittest.TestCase):

    def test_xss_detector_init(self):
        d = XSSDetector()
        self.assertEqual(d.name, "xss")
        self.assertEqual(d.category, "XSS")
        self.assertGreater(len(d.PAYLOADS), 0)

    def test_sqli_detector_init(self):
        d = SQLiDetector()
        self.assertEqual(d.name, "sqli")
        self.assertEqual(d.category, "SQLi")
        self.assertGreater(len(d.ERROR_PAYLOADS), 0)
        self.assertGreater(len(d.TIME_PAYLOADS), 0)

    def test_ssrf_detector_init(self):
        d = SSRFDetector()
        self.assertEqual(d.name, "ssrf")
        self.assertEqual(d.category, "SSRF")
        self.assertGreater(len(d.INTERNAL_PAYLOADS), 0)

    def test_xxe_detector_init(self):
        d = XXEDetector()
        self.assertEqual(d.name, "xxe")
        self.assertEqual(d.category, "XXE")
        self.assertGreater(len(d.XML_PAYLOADS), 0)

    def test_rce_detector_init(self):
        d = RCEDetector()
        self.assertEqual(d.name, "rce")
        self.assertEqual(d.category, "RCE")
        self.assertGreater(len(d.COMMAND_PAYLOADS), 0)

    def test_nosqli_detector_init(self):
        d = NoSQLiDetector()
        self.assertEqual(d.name, "nosqli")
        self.assertEqual(d.category, "NoSQLi")
        self.assertGreater(len(d.MONGO_PAYLOADS), 0)

    def test_ssti_detector_init(self):
        d = SSTIDetector()
        self.assertEqual(d.name, "ssti")
        self.assertEqual(d.category, "SSTI")

    def test_lfi_detector_init(self):
        d = LFIDetector()
        self.assertEqual(d.name, "lfi")
        self.assertEqual(d.category, "LFI")

    def test_infoleak_detector_init(self):
        d = InfoLeakDetector()
        self.assertEqual(d.name, "infoleak")
        self.assertEqual(d.category, "InfoLeak")


class TestDetectorTestMethod(unittest.TestCase):

    def test_xss_detector_has_test_method(self):
        d = XSSDetector()
        self.assertTrue(hasattr(d, "test"))
        self.assertTrue(callable(d.test))

    def test_sqli_detector_has_test_method(self):
        d = SQLiDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_ssrf_detector_has_test_method(self):
        d = SSRFDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_xxe_detector_has_test_method(self):
        d = XXEDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_rce_detector_has_test_method(self):
        d = RCEDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_nosqli_detector_has_test_method(self):
        d = NoSQLiDetector()
        self.assertTrue(hasattr(d, "test"))


if __name__ == "__main__":
    unittest.main()
