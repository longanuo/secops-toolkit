"""目标侦察脚本 - memblaze.com"""
import requests
import urllib3
import re
from secops_core.config import HTTP_USER_AGENT

urllib3.disable_warnings()
headers = {"User-Agent": HTTP_USER_AGENT}
BASE = "https://www.memblaze.com"

# 1. robots.txt
print("=== robots.txt ===")
try:
    r = requests.get(f"{BASE}/robots.txt", headers=headers, timeout=10, verify=False)
    print(f"Status: {r.status_code}")
    print(r.text[:2000])
except Exception as e:
    print(f"Error: {e}")

# 2. sitemap.xml 提取链接
print("\n=== sitemap.xml URL 提取 ===")
try:
    r = requests.get(f"{BASE}/sitemap.xml", headers=headers, timeout=10, verify=False)
    urls = re.findall(r'<loc>(.*?)</loc>', r.text)
    print(f"Found {len(urls)} URLs in sitemap")
    for u in urls[:50]:
        print(f"  {u}")
    if len(urls) > 50:
        print(f"  ... and {len(urls) - 50} more")
except Exception as e:
    print(f"Error: {e}")

# 3. 敏感路径探测
print("\n=== 敏感路径探测 ===")
paths = [
    "/admin", "/login", "/api", "/wp-admin", "/wp-login.php",
    "/.env", "/.git/config", "/.git/HEAD", "/server-status",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/console", "/actuator", "/actuator/health", "/swagger-ui.html",
    "/api/v1", "/api/docs", "/graphql", "/.DS_Store",
    "/backup.zip", "/database.sql", "/config.php", "/web.config",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/auth/login", "/support/download", "/about-company/news",
    "/editor", "/ckeditor", "/kindeditor", "/ueditor",
    "/install", "/setup", "/readme.html", "/README.md",
    "/package.json", "/composer.json", "/Gemfile",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
]
for p in paths:
    try:
        r = requests.get(f"{BASE}{p}", headers=headers, timeout=8, verify=False, allow_redirects=False)
        if r.status_code != 404:
            print(f"  {r.status_code} {p} ({len(r.content)} bytes)")
    except:
        pass

# 4. HTTP 方法检查
print("\n=== HTTP 方法 ===")
for method in ["OPTIONS", "TRACE"]:
    try:
        r = requests.request(method, f"{BASE}/cn/", headers=headers, timeout=8, verify=False)
        print(f"  {method}: {r.status_code}")
        if method == "OPTIONS":
            allow = r.headers.get("Allow", "N/A")
            print(f"    Allow: {allow}")
    except Exception as e:
        print(f"  {method}: {e}")

# 5. 响应头安全分析
print("\n=== 安全响应头检查 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    print(f"  Server: {r.headers.get('Server', 'N/A')}")
    print(f"  X-Powered-By: {r.headers.get('X-Powered-By', 'N/A')}")
    print(f"  Content-Security-Policy: {r.headers.get('Content-Security-Policy', 'MISSING')}")
    print(f"  X-Frame-Options: {r.headers.get('X-Frame-Options', 'MISSING')}")
    print(f"  X-Content-Type-Options: {r.headers.get('X-Content-Type-Options', 'MISSING')}")
    print(f"  X-XSS-Protection: {r.headers.get('X-XSS-Protection', 'MISSING')}")
    print(f"  Strict-Transport-Security: {r.headers.get('Strict-Transport-Security', 'MISSING')}")
    print(f"  Referrer-Policy: {r.headers.get('Referrer-Policy', 'MISSING')}")
    print(f"  Permissions-Policy: {r.headers.get('Permissions-Policy', 'MISSING')}")
    print(f"  Set-Cookie: {r.headers.get('Set-Cookie', 'N/A')}")
    # Check all Set-Cookie headers
    if "Set-Cookie" in r.headers:
        print(f"  Cookie flags check:")
        cookie = r.headers["Set-Cookie"]
        if "Secure" not in cookie:
            print(f"    [!] Cookie missing Secure flag")
        if "HttpOnly" not in cookie:
            print(f"    [!] Cookie missing HttpOnly flag")
        if "SameSite" not in cookie:
            print(f"    [!] Cookie missing SameSite attribute")
except Exception as e:
    print(f"Error: {e}")

# 6. 表单和输入点发现
print("\n=== 页面表单和输入点 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', r.text, re.IGNORECASE)
    inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', r.text, re.IGNORECASE)
    print(f"  Forms: {forms}")
    print(f"  Input fields: {inputs}")
except Exception as e:
    print(f"Error: {e}")

# 7. 子域名和子页面中带参数的链接
print("\n=== 带参数的链接 ===")
try:
    r = requests.get(f"{BASE}/cn/", headers=headers, timeout=10, verify=False)
    param_urls = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', r.text, re.IGNORECASE)
    for u in set(param_urls):
        print(f"  {u}")
except Exception as e:
    print(f"Error: {e}")
