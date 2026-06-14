import re
import os
import requests
from datetime import datetime

def fetch_malicious_ips(limit=2000):
    """
    拉取 stamparm/ipsum 恶意IP库
    :param limit: 最大获取条数
    :return: 恶意IP的列表
    """
    url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
    print(f"[*] 正在拉取威胁情报恶意IP列表: {url}")
    
    ips = []
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if parts:
                    ip = parts[0]
                    if ipv4_pattern.match(ip):
                        ips.append(ip)
                        if len(ips) >= limit:
                            break
            print(f"[*] 成功获取 {len(ips)} 条恶意 IP 记录。")
        else:
            print(f"[!] 拉取失败，HTTP 状态码: {response.status_code}")
    except Exception as e:
        print(f"[!] 网络请求异常，无法拉取威胁情报: {str(e)}")
        
    return ips

def fetch_payloads(owner, repo, path):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            return response.text.splitlines()
    except:
        pass
    return []

def extract_xss_patterns(payloads):
    patterns = set()
    for payload in payloads:
        # 简单提取常见的 XSS 触发属性
        matches = re.findall(r'<(?:\w+)[^>]*(on\w+)=', payload, re.I)
        patterns.update([m.lower() for m in matches])
    return list(patterns)

def generate_nginx_waf():
    """提炼漏洞特征并生成Nginx WAF配置"""
    print("[*] 正在从 payloadbox 拉取 XSS 攻击向量...")
    xss_payloads = fetch_payloads("payloadbox", "xss-payload-list", "xss-payload-list.txt")
    if not xss_payloads:
        print("[!] 无法拉取 XSS 载荷，可能网络超时。使用内置 fallback 规则。")
        patterns = ["onerror", "onload", "onclick", "onmouseover"]
    else:
        patterns = extract_xss_patterns(xss_payloads)
        if not patterns:
            patterns = ["onerror", "onload", "onclick", "onmouseover"] # fallback
        
    print(f"[*] 成功提炼 {len(patterns)} 个 XSS 高频触发词特征。")
    
    conf_path = "secops_nginx_waf.conf"
    
    config = []
    config.append("# SecOps 自动提炼的 Nginx WAF 规则")
    config.append(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config.append("map $args $xss_detected {")
    config.append("    default 0;")
    
    for pat in patterns:
        config.append(f"    ~*{pat} 1;")
    config.append("}")
    
    config.append("server {")
    config.append("    # ... existing config ...")
    config.append("    if ($xss_detected) {")
    config.append("        return 403;")
    config.append("    }")
    config.append("}")
    
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write("\n".join(config))
    print(f"[*] Nginx WAF 规则已生成: {os.path.abspath(conf_path)}")
    return True
