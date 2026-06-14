# GitHub 情报学习模式：攻防项目自动分析与防御转化

## 核心理念

从GitHub攻防项目中学习的目标是**提取防御视角**：
- 攻击者用了什么技术 → 如何检测这种技术
- 漏洞的网络特征是什么 → 如何在防火墙层拦截
- 攻击代码的模式是什么 → 转化为WAF/IDS规则

---

## 优质攻防仓库推荐列表

### 漏洞与利用（学习防御）
```
https://github.com/vulhub/vulhub          # 真实CVE复现环境
https://github.com/payloadbox/xss-payload-list  # XSS payload（用于WAF规则提取）
https://github.com/swisskyrepo/PayloadsAllTheThings  # 全攻击技术参考
https://github.com/danielmiessler/SecLists         # 字典/payload合集
https://github.com/projectdiscovery/nuclei-templates  # 漏洞检测模板（直接可用）
```

### 防御与加固
```
https://github.com/CISOfy/lynis           # 系统安全审计
https://github.com/dev-sec/ansible-collection-hardening  # 自动化加固
https://github.com/fail2ban/fail2ban      # 暴力破解防护
https://github.com/crowdsecurity/crowdsec # 现代IPS（推荐！）
https://github.com/OWASP/ModSecurity-Core-Rule-Set  # WAF规则集
```

### 威胁情报
```
https://github.com/firehol/blocklist-ipsets  # IP黑名单（直接用于防火墙）
https://github.com/stamparm/ipsum            # 每日更新恶意IP列表
https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker  # 恶意爬虫规则
https://github.com/stamparm/maltrail         # 恶意流量检测
```

### CTF与技能大赛资源
```
https://github.com/ctf-wiki/ctf-wiki      # CTF知识库（中文）
https://github.com/0xfeeddeadbeef/ctf-tools  # CTF工具集
https://github.com/NSSCTF                 # 国内CTF题库
```

---

## 自动学习流程

### 方案一：Nuclei模板学习（推荐，直接可用）
```bash
# 安装nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# 或
apt install nuclei -y

# 更新模板库
nuclei -update-templates

# 浏览模板结构（学习漏洞特征）
ls ~/.local/nuclei-templates/
# 类别：cves/, technologies/, vulnerabilities/, network/, ...

# 提取HTTP请求特征（转化为WAF规则的原材料）
grep -r "path:" ~/.local/nuclei-templates/cves/ | head -20
grep -r "headers:" ~/.local/nuclei-templates/ | grep -i "User-Agent" | head -10

# 对自己的服务器跑nuclei扫描（已授权）
nuclei -target http://your-server.com -severity high,critical
```

### 方案二：自动爬取攻防项目脚本
```python
#!/usr/bin/env python3
# github_intel_fetcher.py
# 从GitHub学习攻击技术特征，转化为防御规则

import requests
import json
import re
from datetime import datetime

GITHUB_TOKEN = "your_token_here"  # 建议用read-only token
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# 目标仓库列表（按类别）
REPOS = {
    "payload_lists": [
        "payloadbox/xss-payload-list",
        "payloadbox/sql-injection-payload-list",
        "payloadbox/command-injection-payload-list"
    ],
    "vuln_environments": [
        "vulhub/vulhub"
    ],
    "threat_intel": [
        "stamparm/ipsum"
    ]
}

def fetch_repo_readme(owner, repo):
    """获取README了解项目背景"""
    url = f"https://api.github.com/repos/{owner}/{repo}/readme"
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        import base64
        content = base64.b64decode(r.json()["content"]).decode("utf-8", errors="ignore")
        return content[:2000]  # 取前2000字
    return ""

def fetch_payloads(owner, repo, path=""):
    """获取payload文件内容"""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{path}"
    r = requests.get(url)
    if r.status_code == 200:
        return r.text.splitlines()
    return []

def extract_xss_patterns(payloads):
    """从XSS payload中提取WAF规则特征"""
    patterns = set()
    for payload in payloads:
        # 提取常见XSS触发词
        matches = re.findall(r'<(\w+)[^>]*(?:on\w+|src|href)=', payload, re.I)
        patterns.update(matches)
    return list(patterns)

def extract_sqli_patterns(payloads):
    """从SQL注入payload提取特征"""
    patterns = set()
    for payload in payloads:
        # 提取UNION/SELECT等关键词
        matches = re.findall(r'\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|CAST|CONVERT|CHAR|CONCAT)\b', 
                             payload, re.I)
        patterns.update([m.upper() for m in matches])
    return list(patterns)

def generate_nftables_rules_from_intel(malicious_ips):
    """从IP威胁情报生成nftables规则"""
    rules = ["# 自动生成的威胁情报黑名单规则"]
    rules.append(f"# 生成时间: {datetime.now().isoformat()}")
    rules.append(f"# IP数量: {len(malicious_ips)}")
    rules.append("")
    rules.append("table inet threat_intel {")
    rules.append("    set malicious_ips {")
    rules.append("        type ipv4_addr")
    rules.append("        flags interval")
    rules.append("        elements = {")
    
    # 分批写入
    for i in range(0, min(len(malicious_ips), 1000), 10):
        batch = malicious_ips[i:i+10]
        rules.append("            " + ", ".join(batch) + ",")
    
    rules.append("        }")
    rules.append("    }")
    rules.append("    chain input {")
    rules.append("        ip saddr @malicious_ips drop")
    rules.append("    }")
    rules.append("}")
    
    return "\n".join(rules)

def main():
    print("[*] 开始GitHub威胁情报学习...")
    
    # 1. 获取恶意IP列表
    print("[*] 获取今日恶意IP黑名单...")
    ip_lines = fetch_payloads("stamparm", "ipsum", "ipsum.txt")
    malicious_ips = [line.split()[0] for line in ip_lines if line and not line.startswith("#")]
    print(f"    获取到 {len(malicious_ips)} 个恶意IP")
    
    # 生成nftables规则
    rules = generate_nftables_rules_from_intel(malicious_ips[:1000])  # 取前1000个
    with open(f"/tmp/threat_intel_{datetime.now().strftime('%Y%m%d')}.nft", "w") as f:
        f.write(rules)
    print(f"    规则已保存: /tmp/threat_intel_{datetime.now().strftime('%Y%m%d')}.nft")
    
    # 2. XSS特征提取
    print("[*] 学习XSS payload特征...")
    xss_payloads = fetch_payloads("payloadbox", "xss-payload-list", "xss-payload-list.txt")
    xss_patterns = extract_xss_patterns(xss_payloads)
    print(f"    提取到 {len(xss_patterns)} 个XSS特征标签")
    
    # 3. 输出学习摘要（供Hermes agent使用）
    summary = {
        "timestamp": datetime.now().isoformat(),
        "intel_sources": len(REPOS),
        "malicious_ips_count": len(malicious_ips),
        "xss_patterns": xss_patterns,
        "generated_rules": [f"/tmp/threat_intel_{datetime.now().strftime('%Y%m%d')}.nft"],
        "recommended_actions": [
            "nft -f /tmp/threat_intel_<date>.nft",
            "查看新规则是否与现有规则冲突",
            "重启nftables服务"
        ]
    }
    
    with open("/tmp/intel_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    
    print("[✓] 情报学习完成，摘要: /tmp/intel_summary.json")
    return summary

if __name__ == "__main__":
    main()
```

### 方案三：自动化定时学习（cron）
```bash
# 每天凌晨2点自动更新威胁情报并应用到防火墙
cat > /etc/cron.d/threat-intel << 'EOF'
0 2 * * * root python3 /opt/cybersec/github_intel_fetcher.py \
  && nft -f /tmp/threat_intel_$(date +%Y%m%d).nft \
  >> /var/log/threat_intel_update.log 2>&1
EOF

# 每周更新nuclei模板并扫描自己的服务
0 3 * * 1 root nuclei -update-templates \
  && nuclei -target http://localhost -severity high,critical \
  -o /var/log/nuclei_scan_$(date +%Y%m%d).txt \
  >> /var/log/nuclei.log 2>&1
```

---

## 将GitHub攻击手法转化为防御规则

### 转化框架
```
攻击手法                    → 检测特征                → 防御规则类型
XSS payload                → HTTP body包含<script>  → WAF/nftables string match
SQL注入                    → 请求含UNION/SELECT      → WAF规则
路径穿越                   → ../../../etc/passwd    → Nginx规则
扫描行为（大量404）         → 短时间大量请求          → fail2ban规则
恶意User-Agent             → 已知扫描工具特征        → Nginx/nftables规则
恶意IP                     → IP地址                 → nftables set
```

### 从vulhub学习后的防御转化示例
```bash
# 学习了 Log4Shell (CVE-2021-44228) 后：
# 攻击特征：HTTP请求头包含 ${jndi:...}
# 防御规则：

# Nginx WAF规则
if ($http_x_forwarded_for ~* "\$\{jndi:") { return 403; }
if ($request_uri ~* "\$\{jndi:") { return 403; }

# nftables应用层过滤（需配合nfqueue）
# 更实用的是在nginx层直接过滤
```

---

## 情报数据库本地维护

```bash
# 创建本地情报数据库目录
mkdir -p /opt/cybersec/intel/{ips,domains,patterns,rules}

# 情报更新脚本
cat > /opt/cybersec/update_intel.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d)
INTEL_DIR="/opt/cybersec/intel"

# 恶意IP
curl -s "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" \
  | grep -v "#" | awk '{print $1}' \
  > $INTEL_DIR/ips/malicious_$DATE.txt

# 保留最近30天
find $INTEL_DIR/ips -mtime +30 -delete

# 合并最近7天去重
cat $INTEL_DIR/ips/malicious_*.txt | sort -u > $INTEL_DIR/ips/combined.txt
echo "合并后恶意IP: $(wc -l < $INTEL_DIR/ips/combined.txt)"
EOF
chmod +x /opt/cybersec/update_intel.sh
```

---

## Hermes Agent 情报学习输出
```json
{
  "mode": "github-intel",
  "learning_session_id": "intel-YYYYMMDD-NNN",
  "sources_analyzed": [{"repo": "<仓库>", "items_extracted": 0}],
  "new_indicators": {
    "malicious_ips": 0,
    "attack_patterns": [],
    "cve_ids": []
  },
  "rules_generated": [{"type": "nftables|waf|nginx|fail2ban", "path": "<路径>", "count": 0}],
  "applied_to_firewall": false,
  "habit_hints": {
    "learning_frequency": "daily|weekly",
    "preferred_sources": ["<常用情报源>"],
    "auto_apply_threshold": "high_confidence_only"
  },
  "next_learning": "<下次学习建议时间>"
}
```