"""CORS 漏洞检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class CORSDetector(BaseDetector):
    """CORS (跨域资源共享) 漏洞检测器"""

    name = "cors"
    category = "CORS"

    # 测试来源
    ORIGIN_PAYLOADS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://subdomain.target.com",
        "https://target.com.evil.com",
        "https://eviltarget.com",
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 测试每个来源
        for origin in self.ORIGIN_PAYLOADS:
            log_audit("CORS_TEST", base_url, f"Origin: {origin}")

            # 构造请求头
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            }

            status, resp_headers, body = http_get(target_url, timeout=8)

            if status == 0:
                continue

            # 检查 CORS 头
            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            acac = resp_headers.get("Access-Control-Allow-Credentials", "")

            # 检测漏洞
            if acao:
                # 情况1: 反射 Origin
                if acao == origin and origin not in ["null", base_url]:
                    severity = "high" if acac.lower() == "true" else "medium"
                    findings.append(Finding(
                        vuln_type="CORS", severity=severity,
                        title=f"CORS Origin 反射漏洞",
                        location=base_url, payload=f"Origin: {origin}",
                        evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                        description=f"服务器反射了攻击者控制的 Origin ({origin})，可窃取用户数据。",
                        remediation="白名单验证 Origin，不要直接反射"
                    ))

                # 情况2: null Origin 被接受
                elif origin == "null" and acao == "null":
                    findings.append(Finding(
                        vuln_type="CORS", severity="medium",
                        title="CORS 接受 null Origin",
                        location=base_url, payload="Origin: null",
                        evidence=f"Access-Control-Allow-Origin: null",
                        description="服务器接受 null Origin，攻击者可通过 sandboxed iframe 利用。",
                        remediation="不要接受 null Origin"
                    ))

                # 情况3: 通配符 *
                elif acao == "*":
                    if acac.lower() == "true":
                        findings.append(Finding(
                            vuln_type="CORS", severity="high",
                            title="CORS 通配符 + Credentials",
                            location=base_url, payload="Origin: *",
                            evidence="Access-Control-Allow-Origin: * with Credentials: true",
                            description="服务器使用通配符 * 且允许凭证，这是不安全的配置。",
                            remediation="使用具体的 Origin 白名单"
                        ))

            time.sleep(0.2)

        return findings
