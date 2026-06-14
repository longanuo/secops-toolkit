"""信息泄露检测器"""
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class InfoLeakDetector(BaseDetector):
    """信息泄露检测器"""

    name = "infoleak"
    category = "InfoLeak"

    SENSITIVE_PATHS = [
        ("/.env", ["DB_PASSWORD", "APP_KEY", "SECRET", "AWS_"]),
        ("/.git/HEAD", ["ref: refs/"]),
        ("/.git/config", ["[core]", "repositoryformatversion"]),
        ("/.svn/entries", ["svn", "dir"]),
        ("/.DS_Store", ["Bud1"]),
        ("/robots.txt", ["Disallow:", "User-agent:"]),
        ("/sitemap.xml", ["<urlset", "<url>"]),
        ("/crossdomain.xml", ["cross-domain-policy"]),
        ("/.well-known/security.txt", ["Contact:", "Security:"]),
        ("/swagger.json", ["swagger", "paths"]),
        ("/openapi.json", ["openapi", "paths"]),
        ("/api-docs", None),
        ("/actuator", ["status", "health"]),
        ("/actuator/health", ["status"]),
        ("/actuator/env", ["property", "source"]),
        ("/console", None),
        ("/debug", None),
        ("/trace", None),
        ("/metrics", None),
        ("/phpinfo.php", ["PHP Version", "phpinfo()"]),
        ("/info.php", ["PHP Version"]),
        ("/server-status", ["Apache Status"]),
        ("/server-info", ["Apache Server Information"]),
        ("/.htaccess", ["RewriteEngine", "AllowOverride"]),
        ("/wp-config.php.bak", ["DB_NAME", "DB_PASSWORD"]),
        ("/backup.sql", ["CREATE TABLE", "INSERT INTO"]),
        ("/dump.sql", ["CREATE TABLE"]),
        ("/admin/", None),
        ("/wp-admin/", None),
        ("/wp-login.php", ["wp-login", "log"]),
    ]

    def test(self, target_url: str) -> List[Finding]:
        findings = []
        parsed = urllib.parse.urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        baseline_size = None

        for path, indicators in self.SENSITIVE_PATHS:
            url = base + path
            log_audit("INFOLEAK", url, f"path={path}")

            status, headers, body = http_get(url, timeout=5)

            if status == 0:
                continue

            if status == 200 and body:
                if baseline_size is None:
                    baseline_size = len(body)

                # SPA 回退检测
                if abs(len(body) - baseline_size) < 100 and path not in ("/robots.txt", "/sitemap.xml"):
                    continue

                if indicators:
                    for indicator in indicators:
                        if indicator in body:
                            findings.append(Finding(
                                vuln_type="InfoLeak",
                                severity="medium" if ".git" in path or ".env" in path else "low",
                                title=f"敏感路径暴露: {path}",
                                location=url, payload="GET " + path,
                                evidence=f"响应包含 '{indicator}' 关键字 ({len(body)} bytes)",
                                description=f"路径 {path} 可访问且包含敏感信息。",
                                remediation="配置 Web 服务器禁止访问敏感路径"
                            ))
                            break
                elif status == 200 and len(body) > 100:
                    if any(kw in path for kw in ["admin", "console", "debug", "actuator", "swagger"]):
                        findings.append(Finding(
                            vuln_type="InfoLeak", severity="low",
                            title=f"敏感路径可访问: {path}",
                            location=url, payload="GET " + path,
                            evidence=f"HTTP {status}, {len(body)} bytes",
                            description=f"路径 {path} 返回了有效响应。",
                            remediation="限制管理接口的访问来源"
                        ))

            time.sleep(0.1)

        return findings
