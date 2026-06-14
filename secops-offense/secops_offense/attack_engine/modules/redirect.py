"""开放重定向检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class RedirectDetector(BaseDetector):
    """开放重定向漏洞检测器"""

    name = "redirect"
    category = "Open Redirect"

    # 重定向参数
    REDIRECT_PARAMS = [
        "redirect", "url", "next", "return", "goto",
        "continue", "target", "dest", "destination",
        "redir", "redirect_url", "redirect_uri",
        "return_url", "return_to", "checkout_url",
        "exit_url", "to", "out", "view", "link",
        "ref", "referer", "site", "page",
    ]

    # 恶意目标
    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%00.target.com",
        "https://evil.com?.target.com",
        "https://evil.com#.target.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]

    # 检测是否被重定向到外部
    def _is_external_redirect(self, location, evil_domain):
        """检查是否重定向到外部"""
        if not location:
            return False
        return evil_domain in location.lower()

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 使用已有的参数
        if params:
            redirect_params = [p for p in params if any(rp in p.lower() for rp in self.REDIRECT_PARAMS)]
        else:
            redirect_params = self.REDIRECT_PARAMS

        evil_domain = "evil.com"

        for param in redirect_params:
            for payload in self.REDIRECT_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("REDIRECT_TEST", test_url, f"param={param}, payload={payload}")
                status, headers, body = http_get(test_url, timeout=8, allow_redirects=False)

                if status == 0:
                    continue

                # 检查 Location 头
                location = headers.get("Location", "")
                if self._is_external_redirect(location, evil_domain):
                    findings.append(Finding(
                        vuln_type="Open Redirect", severity="medium",
                        title=f"开放重定向漏洞 - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence=f"Location: {location}",
                        description=f"参数 {param} 允许重定向到外部域名。",
                        remediation="实施 URL 白名单验证，禁止重定向到外部域名"
                    ))
                    break

                # 检查 3xx 响应码
                if 300 <= status < 400:
                    if self._is_external_redirect(body, evil_domain):
                        findings.append(Finding(
                            vuln_type="Open Redirect", severity="medium",
                            title=f"开放重定向漏洞 - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"响应包含外部域名: {evil_domain}",
                            description=f"参数 {param} 允许重定向到外部域名。",
                            remediation="实施 URL 白名单验证"
                        ))
                        break

                time.sleep(ATTACK_DELAY)

        return findings
