import re
import os

def analyze_http_traffic(filepath):
    """静态分析原始 HTTP 报文，辅助发现安全漏洞"""
    if not os.path.exists(filepath):
        print(f"[!] 找不到流量文件: {filepath}")
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"[!] 读取失败: {e}")
        return

    print(f"\n[*] 正在审计 HTTP 流量: {filepath}")
    
    # 简单的分块：头部和 Body
    parts = content.split("\n\n", 1)
    if len(parts) == 1:
        parts = content.split("\r\n\r\n", 1)
        
    headers_raw = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    headers = {}
    for line in headers_raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    findings = []

    # 1. CORS 配置不当
    if headers.get("access-control-allow-origin") == "*":
        findings.append("[CORS] 存在 Access-Control-Allow-Origin: *，若存在凭证传输可能导致跨域数据劫持。")

    # 2. 敏感指纹泄露
    if "server" in headers:
        findings.append(f"[信息泄露] Server 头暴露了服务端指纹: {headers['server']}")
    if "x-powered-by" in headers:
        findings.append(f"[信息泄露] X-Powered-By 暴露了应用框架: {headers['x-powered-by']}")

    # 3. 缺失的基础安全头 (主要查响应包)
    if headers_raw.startswith("HTTP/"):
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append("[配置缺陷] 缺失 X-Frame-Options 和 CSP，可能存在 Clickjacking (点击劫持) 风险。")
        if "strict-transport-security" not in headers:
            findings.append("[配置缺陷] 缺失 HSTS (Strict-Transport-Security) 响应头。")

    # 4. 敏感数据正则匹配 (Body)
    if body:
        # 匹配看起来像 JWT 的字符串
        jwt_pattern = r"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"
        jwts = re.findall(jwt_pattern, body)
        if jwts:
            findings.append(f"[敏感数据] 在 Body 中发现类似 JWT Token 的数据 (共 {len(jwts)} 处)。")
            
        # 简单匹配内网 IP
        internal_ip = r"(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"
        ips = set(re.findall(internal_ip, body))
        if ips:
            findings.append(f"[信息泄露] Body 中泄漏了内网 IP 地址: {', '.join(ips)}")

    if not findings:
        print("  [-] 静态审计未发现明显的表层安全问题。")
    else:
        print("\n[!] 发现以下潜在的安全面，建议手工深入验证:")
        for f in findings:
            print(f"  -> {f}")
