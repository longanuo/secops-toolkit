"""新模块单元测试"""
import unittest
from secops_offense.attack_engine.modules.jwt import JWTDetector
from secops_offense.attack_engine.modules.idor import IDORDetector
from secops_offense.attack_engine.modules.cors import CORSDetector
from secops_offense.attack_engine.modules.redirect import RedirectDetector


class TestJWTDetector(unittest.TestCase):

    def test_jwt_detector_init(self):
        d = JWTDetector()
        self.assertEqual(d.name, "jwt")
        self.assertEqual(d.category, "JWT")

    def test_jwt_has_test_method(self):
        d = JWTDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_decode_jwt_payload(self):
        d = JWTDetector()
        # Valid JWT payload
        token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"
        payload = d._decode_jwt_payload(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["user"], "admin")

    def test_find_jwt_tokens(self):
        d = JWTDetector()
        text = 'token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature'
        tokens = d._find_jwt_tokens(text)
        self.assertEqual(len(tokens), 1)


class TestIDORDetector(unittest.TestCase):

    def test_idor_detector_init(self):
        d = IDORDetector()
        self.assertEqual(d.name, "idor")
        self.assertEqual(d.category, "IDOR")

    def test_idor_has_test_method(self):
        d = IDORDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_extract_id_params(self):
        d = IDORDetector()
        url = "https://example.com/page?id=123&name=test"
        params = d._extract_id_params(url)
        self.assertEqual(len(params), 1)
        self.assertEqual(params[0][0], "id")


class TestCORSDetector(unittest.TestCase):

    def test_cors_detector_init(self):
        d = CORSDetector()
        self.assertEqual(d.name, "cors")
        self.assertEqual(d.category, "CORS")

    def test_cors_has_test_method(self):
        d = CORSDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_cors_origin_payloads(self):
        d = CORSDetector()
        self.assertGreater(len(d.ORIGIN_PAYLOADS), 0)
        self.assertIn("https://evil.com", d.ORIGIN_PAYLOADS)


class TestRedirectDetector(unittest.TestCase):

    def test_redirect_detector_init(self):
        d = RedirectDetector()
        self.assertEqual(d.name, "redirect")
        self.assertEqual(d.category, "Open Redirect")

    def test_redirect_has_test_method(self):
        d = RedirectDetector()
        self.assertTrue(hasattr(d, "test"))

    def test_redirect_params(self):
        d = RedirectDetector()
        self.assertIn("redirect", d.REDIRECT_PARAMS)
        self.assertIn("url", d.REDIRECT_PARAMS)
        self.assertIn("next", d.REDIRECT_PARAMS)


if __name__ == "__main__":
    unittest.main()
