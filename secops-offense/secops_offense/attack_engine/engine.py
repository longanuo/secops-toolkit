"""漏洞自动验证引擎主类"""
import json
import random
import string
import urllib.parse
from datetime import datetime
from pathlib import Path
from secops_core.logger import get_logger
from secops_core.http_client import http_get
from secops_core.config import REPORT_DIR
from secops_offense.attack_engine.auth import (
    check_auth, log_audit, get_audit_log, request_authorization
)
from secops_offense.attack_engine.modules.xss import XSSDetector
from secops_offense.attack_engine.modules.sqli import SQLiDetector
from secops_offense.attack_engine.modules.ssti import SSTIDetector
from secops_offense.attack_engine.modules.lfi import LFIDetector
from secops_offense.attack_engine.modules.infoleak import InfoLeakDetector
from secops_offense.attack_engine.modules.ssrf import SSRFDetector
from secops_offense.attack_engine.modules.xxe import XXEDetector
from secops_offense.attack_engine.modules.rce import RCEDetector
from secops_offense.attack_engine.modules.nosqli import NoSQLiDetector
from secops_offense.attack_engine.modules.jwt import JWTDetector
from secops_offense.attack_engine.modules.idor import IDORDetector
from secops_offense.attack_engine.modules.cors import CORSDetector
from secops_offense.attack_engine.modules.redirect import RedirectDetector
from secops_offense.attack_engine.modules.crlf import CRLFDetector
from secops_offense.attack_engine.modules.deserialization import DeserializationDetector
from secops_offense.attack_engine.modules.ldap import LDAPDetector
from secops_offense.attack_engine.modules.subdomain_takeover import SubdomainTakeoverDetector
from secops_offense.attack_engine.browser_engine import BrowserEngine

log = get_logger("attack_engine")


class AttackEngine:
    """
    漏洞自动验证引擎主类
    用法：
        engine = AttackEngine("https://target.com")
        if engine.authorize():
            results = engine.run_all()
            engine.report()
    """

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.findings = []
        self.start_time = None
        self.end_time = None
        self._baseline_body = None
        self._baseline_size = None
        self._is_spa = False

        # 检测器注册表
        self._detectors = {
            "xss": XSSDetector,
            "sqli": SQLiDetector,
            "ssti": SSTIDetector,
            "lfi": LFIDetector,
            "ssrf": SSRFDetector,
            "xxe": XXEDetector,
            "rce": RCEDetector,
            "nosqli": NoSQLiDetector,
            "infoleak": InfoLeakDetector,
            "jwt": JWTDetector,
            "idor": IDORDetector,
            "cors": CORSDetector,
            "redirect": RedirectDetector,
            "crlf": CRLFDetector,
            "deserialization": DeserializationDetector,
            "ldap": LDAPDetector,
            "subdomain_takeover": SubdomainTakeoverDetector,
        }

    def authorize(self) -> bool:
        """获取授权"""
        # 检查是否已经授权（用于 MCP 服务器模式）
        if check_auth(self.target_url):
            return True
        return request_authorization(self.target_url)

    def _detect_spa(self):
        """检测目标是否为 SPA 应用"""
        parsed = urllib.parse.urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        _, _, self._baseline_body = http_get(self.target_url, timeout=8)
        self._baseline_size = len(self._baseline_body)

        rand_path = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
        _, _, rand_body = http_get(base + rand_path, timeout=5)

        if rand_body and abs(len(rand_body) - self._baseline_size) < 100:
            self._is_spa = True
            log.info(f"  [SPA 检测] 目标疑似 SPA 应用 (基准 {self._baseline_size} bytes)")
        else:
            self._is_spa = False

    def run_all(self, modules: list = None):
        """运行所有检测模块"""
        if not check_auth(self.target_url):
            return []

        self.start_time = datetime.now()
        self._detect_spa()

        if modules is None:
            modules = list(self._detectors.keys())

        print(f"\n  [引擎启动] 目标: {self.target_url}")
        print(f"  [模块数] {len(modules)} 个检测模块\n")

        for mod_name in modules:
            if mod_name not in self._detectors:
                print(f"  [跳过] 未知模块: {mod_name}")
                continue

            detector_cls = self._detectors[mod_name]
            detector = detector_cls()
            print(f"  [{mod_name.upper()}] {detector_cls.__name__}...")

            try:
                module_findings = detector.test(self.target_url)
                self.findings.extend(module_findings)

                if module_findings:
                    for f in module_findings:
                        print(str(f))
                else:
                    print(f"    未发现漏洞")
            except Exception as e:
                log.error(f"模块 {mod_name} 执行出错: {e}")
                print(f"    [错误] {e}")

            print()

        self.end_time = datetime.now()
        return self.findings

    def run_browser_scan(self, modules=None):
        """浏览器模式扫描 - 用于 SPA 应用"""
        from secops_offense.attack_engine.auth import check_auth
        if not check_auth(self.target_url):
            return []

        self.start_time = datetime.now()
        browser = BrowserEngine(self.target_url)

        if not browser.start():
            log.error("浏览器引擎启动失败，回退到普通模式")
            return self.run_all(modules)

        page_info = browser.get_page_info()
        print(f"\n  [浏览器引擎] 页面加载完成")
        print(f"    标题: {page_info['title']}")
        print(f"    SPA: {page_info['is_spa']}")
        print(f"    输入字段: {page_info['input_fields']}")
        print(f"    网络请求: {page_info['network_requests']}")
        print(f"    渲染大小: {page_info['rendered_size']} bytes")

        if modules is None:
            modules = ["xss", "infoleak"]

        print()

        if "xss" in modules:
            print("  [XSS] 浏览器模式 XSS 检测...")
            xss_findings = browser.scan_xss()
            self.findings.extend(xss_findings)
            if xss_findings:
                for f in xss_findings:
                    print(str(f))
            else:
                print("    未发现 XSS 漏洞")
            print()

        if "infoleak" in modules:
            print("  [INFOLEAK] 浏览器模式信息泄露检测...")
            info_findings = browser.scan_infoleak()
            self.findings.extend(info_findings)
            if info_findings:
                for f in info_findings:
                    print(str(f))
            else:
                print("    未发现信息泄露")
            print()

        # 动态攻击: API fuzz / 管理后台发现 / 认证绕过
        print("  [DYNAMIC] 动态攻击测试...")
        try:
            dynamic_findings = browser.scan_dynamic()
            self.findings.extend(dynamic_findings)
            if dynamic_findings:
                for f in dynamic_findings:
                    print(str(f))
            else:
                print("    动态测试未发现漏洞")
        except Exception as e:
            log.error(f"动态攻击出错: {e}")
            print(f"    [错误] {e}")
        print()

        api_endpoints = browser.discover_api_endpoints()
        if api_endpoints:
            print(f"  [API] 发现 {len(api_endpoints)} 个 API 端点:")
            for ep in api_endpoints[:10]:
                print(f"    - {ep}")
            print()

        browser.stop()
        self.end_time = datetime.now()
        return self.findings


    def report(self):
        """输出测试报告"""
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0

        print("\n" + "=" * 60)
        print("  漏洞验证报告")
        print("=" * 60)
        print(f"  目标: {self.target_url}")
        print(f"  时间: {self.start_time} ~ {self.end_time}")
        print(f"  耗时: {duration:.1f} 秒")
        print(f"  审计日志: {len(get_audit_log())} 条操作记录")
        print()

        if not self.findings:
            print("  结果: 未发现漏洞 (基础检测)")
            print("  建议: 使用更深度的工具 (sqlmap/nuclei/BurpSuite) 进一步测试")
            return

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

        print(f"  发现 {len(self.findings)} 个漏洞:\n")
        for i, finding in enumerate(sorted_findings, 1):
            print(f"  #{i}")
            print(str(finding))
            print()

        stats = {}
        for f in self.findings:
            stats[f.severity] = stats.get(f.severity, 0) + 1

        print(f"  统计: ", end="")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in stats:
                print(f"{sev}:{stats[sev]} ", end="")
        print()

    def get_findings_json(self) -> dict:
        return {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "total": len(self.findings),
            "audit_log_count": len(get_audit_log()),
        }

    def save_report(self, output_dir=None) -> tuple:
        if output_dir is None:
            output_dir = Path(REPORT_DIR)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urllib.parse.urlparse(self.target_url).netloc.replace(":", "_")

        json_path = output_dir / f"attack_report_{domain}_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.get_findings_json(), f, indent=2, ensure_ascii=False)

        md_path = output_dir / f"attack_report_{domain}_{timestamp}.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self._generate_markdown_report())

        print(f"\n  报告已保存:")
        print(f"    JSON: {json_path}")
        print(f"    Markdown: {md_path}")
        return str(json_path), str(md_path)

    def _generate_markdown_report(self) -> str:
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0

        md = f"""# 漏洞自动验证报告

**目标**: {self.target_url}
**时间**: {self.start_time}
**耗时**: {duration:.1f} 秒
**发现**: {len(self.findings)} 个漏洞

---

## 漏洞清单

| # | 严重程度 | 类型 | 标题 | 位置 |
|---|---------|------|------|------|
"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

        for i, f in enumerate(sorted_findings, 1):
            md += f"| {i} | {f.severity} | {f.vuln_type} | {f.title} | {f.location[:60]} |\n"

        md += "\n---\n\n## 详细发现\n\n"
        for i, f in enumerate(sorted_findings, 1):
            md += f"""### #{i} [{f.severity.upper()}] {f.title}

- **类型**: {f.vuln_type}
- **位置**: {f.location}
- **Payload**: `{f.payload[:200]}`
- **证据**: {f.evidence}
- **描述**: {f.description}
- **修复建议**: {f.remediation}

---

"""

        md += f"\n## 审计日志\n\n共 {len(get_audit_log())} 条操作记录。\n"
        return md


def start_attack(target_url: str = None, modules: list = None, browser_mode: bool = None):
    """
    启动漏洞验证引擎
    browser_mode: True=强制浏览器模式, False=强制urllib模式, None=自动检测
    """
    if not target_url:
        target_url = input("  请输入目标 URL: ").strip()

    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    engine = AttackEngine(target_url)

    if not engine.authorize():
        return None

    # 自动检测是否需要浏览器模式
    if browser_mode is None:
        browser_mode = "#" in target_url or "spa" in target_url.lower()

    if browser_mode:
        print("  [模式] 使用浏览器引擎 (SPA 模式)")
        engine.run_browser_scan(modules=modules)
    else:
        engine.run_all(modules=modules)

    engine.report()
    engine.save_report()

    return engine
