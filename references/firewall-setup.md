# 防火墙模式：从零搭建与智能优化

## 方案选型

你目前还没有防火墙，推荐 **nftables** 作为主防火墙：

```
nftables:
  ✓ Linux 5.2+ 内核原生（现代标准）
  ✓ 语法比iptables更清晰
  ✓ 支持sets（可高效存储数万条IP规则）
  ✓ 支持原子规则替换（热更新不丢包）
  ✓ 与CrowdSec/fail2ban深度集成

搭配组件（推荐）：
  fail2ban  → 暴力破解自动封禁
  CrowdSec  → 社区威胁情报 + 自动响应（现代fail2ban替代）
  Nginx     → 应用层WAF（ModSecurity规则集）
```

---

## 第一步：nftables 基础安装

```bash
# 安装
apt install nftables -y
systemctl enable nftables

# 验证版本
nft --version  # 需要 >= 0.9.3

# 备份现有规则（如果有iptables规则）
iptables-save > /root/iptables.backup.$(date +%Y%m%d)
```

---

## 第二步：基础规则集（生产就绪模板）

```bash
# /etc/nftables.conf
# 个人服务器基础防火墙规则
# 根据实际服务修改 OPEN_TCP_PORTS 和 OPEN_UDP_PORTS

cat > /etc/nftables.conf << 'NFTEOF'
#!/usr/sbin/nft -f
flush ruleset

# ========================================
# 变量定义（修改这里适配你的环境）
# ========================================

# 管理IP白名单（你的家/公司IP，填写后SSH更安全）
define ADMIN_IPS = { 1.2.3.4, 5.6.7.8 }  # 替换为你的IP

# 对外开放的TCP端口
define OPEN_TCP_PORTS = { 80, 443, 22222 }  # 80=HTTP, 443=HTTPS, 22222=SSH

# 对外开放的UDP端口
define OPEN_UDP_PORTS = { 53 }  # DNS（如果你运行DNS服务）

# ========================================
# 主表：处理所有网络流量
# ========================================
table inet main {

    # ---- 威胁情报IP黑名单集合（由脚本动态更新）----
    set blocked_ips {
        type ipv4_addr
        flags interval
        auto-merge
        # 由 /opt/cybersec/update_firewall.sh 自动填充
    }

    # ---- 暴力破解临时封禁集合（fail2ban使用）----
    set brute_force_ban {
        type ipv4_addr
        flags timeout
        timeout 1h   # 1小时后自动解封
    }

    # ---- 速率限制：记录最近连接 ----
    set tcp_conntrack {
        type ipv4_addr
        flags dynamic, timeout
        timeout 60s
    }

    # ======== INPUT链：处理进入本机的流量 ========
    chain input {
        type filter hook input priority 0; policy drop  # 默认拒绝

        # 1. 已建立连接放行（性能优化，必须在最前）
        ct state established,related accept

        # 2. 丢弃无效包
        ct state invalid drop

        # 3. 本地回环放行
        iif lo accept

        # 4. 威胁情报黑名单（最高优先级封禁）
        ip saddr @blocked_ips drop

        # 5. 暴力破解封禁
        ip saddr @brute_force_ban drop

        # 6. 管理员IP白名单（SSH特权访问）
        ip saddr $ADMIN_IPS tcp dport 22222 accept

        # 7. ICMP（允许ping，便于网络诊断）
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept

        # 8. 开放服务端口（含速率限制）
        tcp dport $OPEN_TCP_PORTS ct state new \
            limit rate over 100/minute \
            add @tcp_conntrack { ip saddr timeout 60s }
        tcp dport $OPEN_TCP_PORTS accept
        udp dport $OPEN_UDP_PORTS accept

        # 9. SSH暴力破解防护（3次失败30分钟内封禁）
        tcp dport 22222 ct state new \
            limit rate over 5/minute burst 3 packets \
            add @brute_force_ban { ip saddr }

        # 10. 记录被丢弃的可疑连接（调试用，生产环境可关闭）
        # log prefix "[nft-drop] " flags all counter drop
    }

    # ======== FORWARD链：本机不做路由，默认丢弃 ========
    chain forward {
        type filter hook forward priority 0; policy drop
    }

    # ======== OUTPUT链：本机发出的流量，默认允许 ========
    chain output {
        type filter hook output priority 0; policy accept

        # 可选：阻止本机访问已知恶意IP（防被控外联）
        ip daddr @blocked_ips drop
    }
}

# ========================================
# DDoS防护表（独立优先级，先于主表执行）
# ========================================
table inet ddos_protect {

    chain prerouting {
        type filter hook prerouting priority -100; policy accept

        # SYN Flood防护
        tcp flags & (fin|syn|rst|ack) == syn \
            limit rate over 1000/second burst 2000 packets drop

        # UDP Flood防护
        ip protocol udp \
            limit rate over 500/second burst 1000 packets drop

        # ICMP Flood防护
        ip protocol icmp \
            limit rate over 50/second burst 100 packets drop

        # 端口扫描检测（Nmap等工具特征）
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg drop  # XMAS扫描
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop                       # NULL扫描
    }
}
NFTEOF

# 应用规则
nft -f /etc/nftables.conf

# 验证规则
nft list ruleset | head -50
```

---

## 第三步：动态更新脚本（与GitHub情报联动）

```bash
cat > /opt/cybersec/update_firewall.sh << 'EOF'
#!/bin/bash
# update_firewall.sh
# 从威胁情报自动更新nftables黑名单
# 配合 github-intel.md 中的情报学习流程使用

set -e
LOG="/var/log/firewall_update.log"
INTEL_FILE="/opt/cybersec/intel/ips/combined.txt"

echo "$(date '+%Y-%m-%d %H:%M:%S') 开始防火墙情报更新" | tee -a $LOG

# 检查情报文件
if [ ! -f "$INTEL_FILE" ]; then
    echo "情报文件不存在，先运行 update_intel.sh" | tee -a $LOG
    exit 1
fi

IP_COUNT=$(wc -l < "$INTEL_FILE")
echo "待添加恶意IP: $IP_COUNT" | tee -a $LOG

# 清空当前黑名单集合
nft flush set inet main blocked_ips 2>/dev/null || true

# 分批添加（nft set 支持大批量，但分批更安全）
TEMP_NFT=$(mktemp)
echo "table inet main {" > $TEMP_NFT
echo "    set blocked_ips {" >> $TEMP_NFT
echo "        type ipv4_addr" >> $TEMP_NFT
echo "        flags interval" >> $TEMP_NFT
echo "        auto-merge" >> $TEMP_NFT
echo "        elements = {" >> $TEMP_NFT

# 验证IP格式后添加
while IFS= read -r ip; do
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "            $ip," >> $TEMP_NFT
    fi
done < "$INTEL_FILE"

echo "        }" >> $TEMP_NFT
echo "    }" >> $TEMP_NFT
echo "}" >> $TEMP_NFT

# 原子更新（不中断现有连接）
nft -f $TEMP_NFT
rm -f $TEMP_NFT

echo "$(date '+%Y-%m-%d %H:%M:%S') 更新完成，已加载 $IP_COUNT 个黑名单IP" | tee -a $LOG

# 输出Hermes agent可读的结果
cat > /tmp/firewall_update_result.json << JSONEOF
{
  "timestamp": "$(date -Iseconds)",
  "action": "threat_intel_update",
  "blocked_ips_count": $IP_COUNT,
  "status": "success",
  "log": "$LOG"
}
JSONEOF
EOF
chmod +x /opt/cybersec/update_firewall.sh
```

---

## 第四步：CrowdSec 安装（现代IPS）

```bash
# CrowdSec = 社区共享威胁情报 + 自动响应
# 安装
curl -s https://install.crowdsec.net | sudo sh
apt install crowdsec crowdsec-firewall-bouncer-nftables -y

# 配置nftables bouncer（自动封禁）
cat > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml << 'EOF'
mode: nftables
pid_dir: /var/run/
update_frequency: 10s
log_mode: file
log_dir: /var/log/
log_level: info
api_url: http://localhost:8080
api_key: YOUR_BOUNCER_KEY  # 由 cscli bouncers add 生成
disable_ipv6: false
deny_action: DROP
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
EOF

# 生成bouncer密钥
cscli bouncers add crowdsec-firewall-bouncer
# 将输出的key填入上面的api_key

systemctl enable crowdsec crowdsec-firewall-bouncer
systemctl start crowdsec crowdsec-firewall-bouncer

# 安装常用场景（自动识别攻击类型）
cscli collections install crowdsecurity/nginx
cscli collections install crowdsecurity/linux
cscli collections install crowdsecurity/sshd
```

---

## 防火墙规则调试与监控

```bash
# 实时监控被拦截的包
nft monitor trace

# 查看规则命中计数
nft list ruleset | grep counter

# 查看黑名单集合
nft list set inet main blocked_ips | wc -l

# 手动临时封禁IP（立即生效）
nft add element inet main blocked_ips { 1.2.3.4 }

# 手动解封
nft delete element inet main blocked_ips { 1.2.3.4 }

# 查看连接追踪状态
conntrack -L | grep ESTABLISHED | wc -l

# 测试规则（不实际应用）
nft -c -f /etc/nftables.conf && echo "规则语法正确"
```

---

## 规则优化策略

### 性能优化
```
1. 状态检测（ct state established）放最前 → 大流量快速放行
2. 使用 sets 存储大量IP（比逐条规则快10倍）
3. 频繁匹配的规则放在链的前面
4. 使用 auto-merge 合并相邻CIDR
```

### 基于学习的动态优化
```python
# 分析防火墙日志，找出高频被封IP的来源国
# 如果某国IP持续攻击，可以考虑添加地理封禁

# 安装geoip工具
apt install mmdb-bin -y
# 下载GeoLite2数据库（需MaxMind免费注册）
# 分析被封IP的地理分布
cat /var/log/nftables_drop.log | awk '{print $NF}' | \
  while read ip; do mmdblookup --file GeoLite2-Country.mmdb \
    --ip $ip country names en 2>/dev/null; done | \
  sort | uniq -c | sort -rn | head -10
```

---

## Hermes Agent 防火墙模式输出
```json
{
  "mode": "firewall",
  "action": "setup|update|optimize|incident_block",
  "firewall_type": "nftables",
  "rule_changes": [
    {"type": "add|remove|modify", "target": "set|chain|rule", "detail": "<变更说明>"}
  ],
  "blocked_ips_total": 0,
  "active_chains": ["input", "output", "forward", "prerouting"],
  "intel_sources_applied": ["<情报来源>"],
  "optimization_applied": ["<优化项>"],
  "habit_hints": {
    "update_frequency": "daily",
    "auto_apply_intel": true,
    "preferred_crowdsec_collections": ["<常用场景>"],
    "whitelist_ips": ["<管理员IP，持久记录>"]
  }
}
```