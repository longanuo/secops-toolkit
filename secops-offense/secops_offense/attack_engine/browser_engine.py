"""
无头浏览器引擎 - 用于 SPA 应用的漏洞检测

解决 urllib 无法执行 JS 的问题：
  - 用 Playwright 启动无头 Chrome
  - 等待 JS 渲染完成，拿到真实 DOM
  - 在渲染后的页面中注入 payload
  - 捕获 XSS 反射、SQL 错误等
"""

import re
import time
import urllib.parse
from typing import List, Dict, Optional, Tuple
from secops_core.logger import get_logger
from secops_core.config import ATTACK_DELAY

log = get_logger("browser_engine")


class BrowserEngine:
    """
    无头浏览器漏洞检测引擎
    
    用法：
        engine = BrowserEngine("https://spa-target.com")
        engine.start()
        findings = engine.scan_xss()
        findings += engine.scan_infoleak()
        engine.stop()
    """

    def __init__(self, target_url: str, headless: bool = True, timeout: int = 15000):
        self.target_url = target_url.rstrip("/")
        self.headless = headless
        self.timeout = timeout
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._rendered_html = ""
        self._is_spa = False
        self._input_fields = []
        self._forms = []
        self._network_logs = []
        self._console_logs = []

    def start(self) -> bool:
        """启动浏览器并加载目标页面"""
        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-web-security", "--ignore-certificate-errors"]
            )
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            self._page = self._context.new_page()

            # 监听网络请求
            self._page.on("request", lambda req: self._network_logs.append({
                "url": req.url, "method": req.method, "type": req.resource_type
            }))
            self._page.on("console", lambda msg: self._console_logs.append({
                "type": msg.type, "text": msg.text
            }))

            log.info(f"浏览器启动，正在加载 {self.target_url}")
            self._page.goto(self.target_url, timeout=self.timeout, wait_until="networkidle")

            # 等待 JS 渲染
            self._page.wait_for_timeout(2000)
            self._rendered_html = self._page.content()

            # 检测 SPA
            self._detect_spa()

            # 提取输入字段
            self._extract_inputs()

            log.info(f"页面加载完成: {len(self._rendered_html)} bytes, SPA={self._is_spa}")
            return True

        except Exception as e:
            log.error(f"浏览器启动失败: {e}")
            return False

    def stop(self):
        """关闭浏览器"""
        try:
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass

    def _detect_spa(self):
        """检测是否为 SPA 应用"""
        body_text = self._page.evaluate("document.body.innerText.trim()")
        app_div = self._page.query_selector('#app, #root, [data-v-app]')
        
        # SPA 特征: 有 #app 容器 + JS 渲染的内容
        if app_div and len(body_text) > 50:
            self._is_spa = True
            log.info("检测到 SPA 应用 (JS 渲染后有实际内容)")
        elif len(self._rendered_html) > 2000 and body_text:
            self._is_spa = True
            log.info("疑似 SPA (大量 JS + 渲染内容)")

    def _extract_inputs(self):
        """提取页面中的输入字段和表单"""
        try:
            # 提取所有可输入元素
            inputs = self._page.query_selector_all(
                'input[type="text"], input[type="search"], input[type="url"], '
                'input[type="email"], input[type="password"], input:not([type]), '
                'textarea, [contenteditable="true"]'
            )
            for inp in inputs:
                try:
                    tag = inp.evaluate("el => el.tagName")
                    inp_type = inp.evaluate("el => el.type || ''")
                    name = inp.evaluate("el => el.name || el.id || el.placeholder || ''")
                    visible = inp.is_visible()
                    if visible:
                        self._input_fields.append({
                            "tag": tag, "type": inp_type, "name": name,
                            "selector": self._build_selector(inp)
                        })
                except Exception:
                    pass

            # 提取表单
            forms = self._page.query_selector_all("form")
            for form in forms:
                try:
                    action = form.evaluate("el => el.action || ''")
                    method = form.evaluate("el => el.method || 'GET'")
                    self._forms.append({"action": action, "method": method})
                except Exception:
                    pass

            log.info(f"发现 {len(self._input_fields)} 个输入字段, {len(self._forms)} 个表单")
        except Exception as e:
            log.warning(f"提取输入字段失败: {e}")

    def _build_selector(self, element) -> str:
        """为元素生成 CSS 选择器"""
        try:
            return element.evaluate("""el => {
                if (el.id) return '#' + el.id;
                if (el.name) return el.tagName.toLowerCase() + '[name="' + el.name + '"]';
                const attrs = [];
                if (el.className) attrs.push('.' + el.className.split(' ')[0]);
                return el.tagName.toLowerCase() + (attrs.length ? attrs.join('') : '');
            }""")
        except Exception:
            return ""

    def get_rendered_text(self) -> str:
        """获取 JS 渲染后的页面文本"""
        try:
            return self._page.evaluate("document.body.innerText")
        except Exception:
            return self._rendered_html

    def get_rendered_html(self) -> str:
        """获取 JS 渲染后的完整 HTML"""
        try:
            return self._page.content()
        except Exception:
            return self._rendered_html

    def get_page_info(self) -> dict:
        """获取页面基础信息"""
        info = {
            "url": self._page.url if self._page else self.target_url,
            "title": "", "is_spa": self._is_spa,
            "input_fields": len(self._input_fields),
            "forms": len(self._forms),
            "network_requests": len(self._network_logs),
            "rendered_size": len(self._rendered_html),
        }
        try:
            info["title"] = self._page.title()
        except Exception:
            pass
        return info

    # ============================================================
    #  XSS 检测 (浏览器模式)
    # ============================================================

    def scan_xss(self, payloads: list = None) -> list:
        """
        在渲染后的页面中检测 XSS
        策略:
          1. URL 参数注入 (反射型)
          2. 输入字段注入 (DOM/存储型)
        """
        from secops_offense.attack_engine.finding import Finding
        findings = []

        if payloads is None:
            payloads = [
                '"><secopsxss>',
                "'><secopsxss>",
                "<secopsxss>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                '" onmouseover=alert(1) x="',
                "javascript:alert(1)",
                "<details open ontoggle=alert(1)>",
            ]

        # 策略1: URL 参数注入
        parsed = urllib.parse.urlparse(self.target_url)
        if parsed.query:
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            for param in params:
                for payload in payloads:
                    test_params = {param: payload}
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_url = f"{base}?{urllib.parse.urlencode(test_params)}"

                    try:
                        self._page.goto(test_url, timeout=self.timeout, wait_until="networkidle")
                        self._page.wait_for_timeout(1000)
                        body = self._page.content()

                        if payload in body and "secopsxss" in payload:
                            findings.append(Finding(
                                vuln_type="XSS", severity="high",
                                title=f"反射型 XSS (浏览器验证) - 参数 {param}",
                                location=test_url, payload=payload,
                                evidence="Payload 在 JS 渲染后的 DOM 中完整出现",
                                description=f"参数 {param} 的输入未经过滤，在 SPA 渲染后仍可注入。",
                                remediation="对所有用户输入进行 HTML 实体编码"
                            ))
                            break
                    except Exception as e:
                        log.debug(f"XSS 测试异常: {e}")

                    time.sleep(ATTACK_DELAY)

        # 策略2: 输入字段注入
        if self._input_fields:
            log.info(f"对 {len(self._input_fields)} 个输入字段进行 XSS 注入测试")
            # 回到原始页面
            try:
                self._page.goto(self.target_url, timeout=self.timeout, wait_until="networkidle")
                self._page.wait_for_timeout(1000)
            except Exception:
                pass

            for field in self._input_fields:
                selector = field.get("selector", "")
                if not selector:
                    continue

                for payload in payloads[:4]:  # 限制数量避免太慢
                    try:
                        el = self._page.query_selector(selector)
                        if not el or not el.is_visible():
                            continue

                        el.click()
                        el.fill(payload)
                        el.press("Enter")
                        self._page.wait_for_timeout(1500)

                        body = self._page.content()
                        if payload in body and "secopsxss" in payload:
                            findings.append(Finding(
                                vuln_type="XSS", severity="high",
                                title=f"DOM/存储型 XSS (浏览器验证) - 字段 {field['name']}",
                                location=self.target_url, payload=payload,
                                evidence=f"Payload 通过输入字段 '{field['name']}' 注入后在页面中出现",
                                description=f"输入字段 '{field['name']}' 存在 XSS 漏洞。",
                                remediation="对用户输入进行 HTML 实体编码，配置 CSP"
                            ))
                            break
                    except Exception as e:
                        log.debug(f"字段注入异常: {e}")

                    time.sleep(ATTACK_DELAY)

        return findings

    # ============================================================
    #  信息泄露检测 (浏览器模式)
    # ============================================================

    def _is_spa_shell(self, body: str) -> bool:
        """判断响应是否是 SPA 回退壳（不是真实内容）"""
        if not body:
            return False
        # SPA 特征: 包含 <div id="app"> 或大量 JS bundle
        spa_indicators = ['<div id="app">', '<div id="root">', 'uni.', '.css">', 'webpackJsonp']
        hit_count = sum(1 for ind in spa_indicators if ind in body)
        return hit_count >= 2

    def scan_infoleak(self) -> list:
        """检测 JS 源码中的敏感信息泄露"""
        from secops_offense.attack_engine.finding import Finding
        findings = []

        # 获取所有 JS 文件 URL
        js_urls = []
        for log_entry in self._network_logs:
            if log_entry.get("type") == "script" and log_entry["url"].endswith(".js"):
                js_urls.append(log_entry["url"])

        # 检查 JS 中的敏感信息
        sensitive_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', "API Key"),
            (r'(?:secret|token|password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']', "Secret/Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
            (r'(?:mongodb|mysql|postgres|redis)://[^\s"\']+', "数据库连接串"),
            (r'(?:192\.168|10\.\d|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+', "内网 IP"),
        ]

        # 检查渲染后的 HTML
        html = self.get_rendered_html()
        for pattern, desc in sensitive_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    vuln_type="InfoLeak", severity="medium",
                    title=f"页面源码泄露: {desc}",
                    location=self.target_url,
                    payload=f"正则匹配: {pattern[:50]}",
                    evidence=f"发现 {len(matches)} 处 {desc}: {matches[0][:80]}",
                    description=f"页面 HTML/JS 中包含 {desc}，可能被攻击者利用。",
                    remediation="从前端代码中移除敏感信息，使用后端代理"
                ))

        # 检查 JS 文件内容
        for js_url in js_urls[:10]:  # 限制数量
            try:
                resp = self._context.request.get(js_url, timeout=5000)
                js_content = resp.text()
                for pattern, desc in sensitive_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    if matches:
                        findings.append(Finding(
                            vuln_type="InfoLeak", severity="medium",
                            title=f"JS 文件泄露: {desc}",
                            location=js_url,
                            payload=f"正则匹配",
                            evidence=f"JS 文件中发现 {len(matches)} 处 {desc}",
                            description=f"JS 文件 {js_url} 包含 {desc}。",
                            remediation="从 JS 构建产物中移除敏感信息"
                        ))
            except Exception:
                pass

        # 检查 .env / .git 等敏感路径
        parsed = urllib.parse.urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        sensitive_paths = ["/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml"]
        for path in sensitive_paths:
            try:
                resp = self._context.request.get(base + path, timeout=3000)
                if resp.status == 200 and len(resp.text()) > 10:
                    if path == "/.env" and ("KEY" in resp.text() or "SECRET" in resp.text()):
                        findings.append(Finding(
                            vuln_type="InfoLeak", severity="critical",
                            title=f"敏感文件暴露: {path}",
                            location=base + path, payload="GET " + path,
                            evidence=f".env 文件可访问，包含敏感配置",
                            description=".env 文件暴露了服务器配置信息。",
                            remediation="配置 Web 服务器禁止访问 .env 文件"
                        ))
                    elif path == "/.git/HEAD":
                        findings.append(Finding(
                            vuln_type="InfoLeak", severity="high",
                            title=f"Git 仓库暴露: {path}",
                            location=base + path, payload="GET " + path,
                            evidence="Git HEAD 文件可访问",
                            description="Git 仓库暴露，攻击者可能恢复源码。",
                            remediation="删除 .git 目录或配置访问限制"
                        ))
            except Exception:
                pass

        return findings

    # ============================================================
    #  动态攻击 (浏览器模式独有)
    # ============================================================

    def scan_robots(self) -> list:
        """
        robots.txt 情报分析:
        - 提取隐藏路径并探测可访问性
        - 提取关联站点
        - 提取 Sitemap 中的子页面
        """
        from secops_offense.attack_engine.robots_parser import (
            parse_robots_txt, probe_hidden_paths, analyze_sitemaps, scan_related_domains,
            generate_robots_report
        )
        from secops_offense.attack_engine.finding import Finding

        findings = []
        robots_data = parse_robots_txt(self.target_url)

        if not robots_data["hidden_paths"] and not robots_data["sitemaps"]:
            log.info("robots.txt 不存在或无有用信息")
            return findings

        # 1. 探测隐藏路径可访问性
        accessible = probe_hidden_paths(self.target_url, robots_data["hidden_paths"])

        # 2. 对可访问的敏感路径生成 Finding
        for p in accessible:
            path = p["path"]
            severity = "low"
            if any(kw in path.lower() for kw in [".git", ".env", "config", "backup", "dump"]):
                severity = "critical"
            elif any(kw in path.lower() for kw in ["admin", "api", "debug", "actuator", "swagger"]):
                severity = "high"
            elif any(kw in path.lower() for kw in ["robots", "sitemap", "login", "register"]):
                severity = "medium"

            if p.get("has_content") or "redirect_to" in p:
                evidence = f"HTTP {p['status']}"
                if "redirect_to" in p:
                    evidence += f" -> {p['redirect_to']}"
                else:
                    evidence += f", {p['size']} bytes"

                findings.append(Finding(
                    vuln_type="RobotsLeak", severity=severity,
                    title=f"robots.txt 暴露路径: {path}",
                    location=p["url"], payload="robots.txt -> " + path,
                    evidence=evidence,
                    description=f"robots.txt 中 Disallow 路径 {path} 可访问，暴露了站点结构。",
                    remediation="不要在 robots.txt 中列出敏感路径"
                ))

        # 3. 分析 Sitemap
        sitemap_urls = analyze_sitemaps(robots_data["sitemaps"])
        if sitemap_urls:
            findings.append(Finding(
                vuln_type="InfoLeak", severity="medium",
                title=f"Sitemap 暴露 {len(sitemap_urls)} 个页面",
                location=robots_data["sitemaps"][0] if robots_data["sitemaps"] else "",
                payload="Sitemap 分析",
                evidence=f"发现 {len(sitemap_urls)} 个可索引页面",
                description="Sitemap 暴露了站点所有页面结构。",
                remediation="从 Sitemap 中移除敏感页面"
            ))

        # 4. 扫描关联站点
        related = scan_related_domains(robots_data["related_domains"])
        for site in related:
            findings.append(Finding(
                vuln_type="InfoLeak", severity="low",
                title=f"关联站点: {site['domain']}",
                location=site["url"], payload="robots.txt Sitemap",
                evidence=f"标题: {site.get('title', 'N/A')}, {site['size']} bytes",
                description=f"robots.txt 中 Sitemap 指向关联站点 {site['domain']}，可扩大攻击面。",
                remediation="不要在 robots.txt 中列出非必要的 Sitemap"
            ))

        # 打印报告
        report = generate_robots_report(robots_data, accessible, sitemap_urls, related)
        print(report)

        return findings

    def scan_dynamic(self) -> list:
        """
        动态攻击: robots.txt 情报 + API fuzz + 管理后台 + 认证绕过 + CORS
        """
        from secops_offense.attack_engine.dynamic_attack import DynamicAttacker

        attacker = DynamicAttacker(self._page, self._context)
        findings = []

        # 0. robots.txt 情报分析
        log.info("分析 robots.txt")
        robots_findings = self.scan_robots()
        findings.extend(robots_findings)

        # 1. 对 API 端点做 fuzz
        api_endpoints = self.discover_api_endpoints()
        if api_endpoints:
            log.info(f"对 {len(api_endpoints)} 个 API 端点进行动态 fuzz")
            findings.extend(attacker.attack_api_endpoints(api_endpoints))

        # 2. 管理后台和敏感路径发现
        log.info("Fuzz 管理后台和敏感路径")
        findings.extend(attacker.fuzz_common_paths(self.target_url))

        # 3. 认证绕过测试
        log.info("测试认证绕过")
        findings.extend(attacker.test_auth_bypass(self.target_url))

        # 4. CORS 配置检测
        log.info("检测 CORS 配置")
        findings.extend(attacker.test_cors_misconfig(self.target_url))

        # 5. 认证突破 (Token 提取 + 默认密码 + JWT + IDOR)
        log.info("认证突破扫描")
        try:
            from secops_offense.attack_engine.auth_breaker import AuthBreaker
            breaker = AuthBreaker(self._page, self._context)
            auth_findings = breaker.full_scan(self.target_url)
            findings.extend(auth_findings)
            if breaker.discovered_tokens:
                log.info(f"  发现 {len(breaker.discovered_tokens)} 个 Token")
            if breaker.discovered_login_urls:
                log.info(f"  发现 {len(breaker.discovered_login_urls)} 个登录接口")
        except Exception as e:
            log.error(f"认证突破出错: {e}")

        return findings

    # ============================================================
    #  API 接口发现 (浏览器模式独有)
    # ============================================================

    def discover_api_endpoints(self) -> list:
        """从网络请求中提取 API 端点"""
        endpoints = set()
        for req in self._network_logs:
            url = req.get("url", "")
            if "/api/" in url or "/v1/" in url or "/v2/" in url:
                endpoints.add(url)
            if req.get("type") in ("xhr", "fetch"):
                endpoints.add(url)
        return list(endpoints)
