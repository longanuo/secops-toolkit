# 服务器运维模式：安全加固与日常运维

## 服务器初始化安全清单（新机必做）

### 第一步：账户与认证加固
```bash
# 创建非root管理账户
adduser secadmin && usermod -aG sudo secadmin

# 禁止root直接SSH登录
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# 使用密钥认证
ssh-keygen -t ed25519 -C "server-admin"
# 将公钥追加到 ~/.ssh/authorized_keys

# 修改SSH端口（可选，减少自动扫描）
sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config
systemctl restart sshd

# 设置强密码策略
apt install libpam-pwquality -y
# 编辑 /etc/security/pwquality.conf:
#   minlen = 12
#   dcredit = -1
#   ucredit = -1
#   lcredit = -1
#   ocredit = -1
```

### 第二步：系统更新与最小化服务
```bash
# 自动安全更新
apt install unattended-upgrades -y
dpkg-reconfigure unattended-upgrades

# 列出并关闭不必要服务
systemctl list-units --type=service --state=running
# 按需禁用：bluetooth, cups, avahi-daemon等
systemctl disable --now bluetooth cups avahi-daemon

# 移除不必要软件包
apt autoremove --purge
```

### 第三步：审计与监控
```bash
# 安装auditd（系统调用审计）
apt install auditd audispd-plugins -y
systemctl enable auditd

# 关键审计规则
cat >> /etc/audit/rules.d/security.rules << 'EOF'
# 监控passwd/shadow修改
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# 监控SSH配置变更
-w /etc/ssh/sshd_config -p wa -k sshd_config

# 监控特权命令
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# 监控网络连接（可选，较多日志）
-a always,exit -F arch=b64 -S connect -k network_connect
EOF
service auditd restart

# 安装fail2ban
apt install fail2ban -y
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
# 在jail.local中配置：
# [sshd]
# enabled = true
# maxretry = 5
# bantime = 3600
systemctl enable fail2ban
```

### 第四步：内核加固（sysctl）
```bash
cat >> /etc/sysctl.d/99-security.conf << 'EOF'
# 禁止IP欺骗
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 禁止ICMP重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# 防SYN Flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# 禁止ping（可选）
# net.ipv4.icmp_echo_ignore_all = 1

# 隐藏内核指针（防信息泄露）
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

# 禁止core dump（防内存转储泄露）
fs.suid_dumpable = 0
EOF
sysctl -p /etc/sysctl.d/99-security.conf
```

---

## 日常巡检流程（每日/每周）

### 快速健康检查脚本
```bash
#!/bin/bash
# health_check.sh - 每日巡检

echo "===== 系统健康检查 $(date) ====="

echo "--- CPU & 内存 ---"
top -bn1 | head -5
free -h

echo "--- 磁盘 ---"
df -h | grep -v tmpfs

echo "--- 异常进程（CPU>50%）---"
ps aux --sort=-%cpu | awk 'NR<=5 && $3>50 {print}'

echo "--- 最近登录 ---"
last | head -10

echo "--- 失败登录尝试 ---"
grep "Failed password" /var/log/auth.log | tail -20
fail2ban-client status sshd 2>/dev/null

echo "--- 监听端口变化 ---"
ss -tlnp | grep -v "127.0.0.1"

echo "--- 定时任务检查 ---"
crontab -l 2>/dev/null
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/

echo "--- 最近修改的配置文件 ---"
find /etc -mtime -1 -type f 2>/dev/null

echo "===== 检查完成 ====="
```

### 日志分析要点
```bash
# SSH暴力破解统计
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# 成功登录审计
grep "Accepted" /var/log/auth.log | tail -20

# sudo使用记录
grep "sudo:" /var/log/auth.log | grep "COMMAND" | tail -20

# 系统错误
journalctl -p err -n 50 --since "24 hours ago"

# Nginx/Apache访问日志异常（扫描特征）
grep -E "(\.php\?|UNION|SELECT|<script|../)" /var/log/nginx/access.log | tail -30
```

---

## 应急响应 Playbook

### 发现入侵迹象时
```bash
# 第一时间：不要关机！先取证
# 1. 隔离（在防火墙层封禁可疑IP，但保持机器运行）

# 2. 保存当前状态快照
netstat -antup > /tmp/ir_netstat.txt
ps auxf > /tmp/ir_processes.txt
who > /tmp/ir_users.txt
last > /tmp/ir_logins.txt
find / -mtime -1 -type f 2>/dev/null > /tmp/ir_recent_files.txt
crontab -l >> /tmp/ir_crontab.txt
cat /etc/crontab /etc/cron.d/* >> /tmp/ir_crontab.txt

# 3. 检查后门
# 隐藏进程
ps -ef | awk '{print $2}' > /tmp/ps_pids.txt
ls /proc | grep -v [^0-9] > /tmp/proc_pids.txt
diff /tmp/ps_pids.txt /tmp/proc_pids.txt  # 差异即隐藏进程

# 检查异常网络连接
ss -antup | grep ESTABLISHED

# 检查SUID文件变化（与基线对比）
find / -perm -4000 -type f 2>/dev/null

# 检查新增账户
grep -E ":[0-9]{4}:" /etc/passwd  # UID >= 1000的账户

# 4. 根据发现的IOC更新防火墙规则
# 参考 firewall-setup.md

# 5. 修复后重置凭证（所有密码+密钥）
```

### Webshell检测
```bash
# 查找PHP webshell特征
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|exec\|passthru\|shell_exec" {} \;

# 查找近期修改的web文件
find /var/www -mtime -7 -type f -name "*.php"

# 使用工具扫描
# ClamAV
clamscan -r --infected /var/www/html
# NeoPI（webshell检测）
python neopi.py -C -T /var/www/html
```

---

## 性能监控与基线

### 关键指标基线记录
```bash
# 初始化基线（首次运行时保存）
cat > /root/baseline_check.sh << 'EOF'
#!/bin/bash
date >> /var/log/baseline.log
echo "CPU cores: $(nproc)" >> /var/log/baseline.log
echo "Memory: $(free -m | awk '/Mem/{print $2}')MB" >> /var/log/baseline.log
echo "Disk:" >> /var/log/baseline.log
df -h >> /var/log/baseline.log
echo "Open ports:" >> /var/log/baseline.log
ss -tlnp >> /var/log/baseline.log
echo "Running services:" >> /var/log/baseline.log
systemctl list-units --type=service --state=running >> /var/log/baseline.log
echo "SUID files:" >> /var/log/baseline.log
find / -perm -4000 -type f 2>/dev/null >> /var/log/baseline.log
EOF
chmod +x /root/baseline_check.sh && /root/baseline_check.sh
```

### 推荐的轻量监控方案
```bash
# Netdata（实时监控，Web UI）
wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh
sh /tmp/netdata-kickstart.sh

# 或使用 Prometheus + Node Exporter（重量级但更完整）
# 适合有多台服务器的场景
```

---

## Hermes Agent 运维模式输出
```json
{
  "mode": "server-ops",
  "task_type": "init_hardening|daily_check|incident_response|performance",
  "server_id": "<服务器标识>",
  "findings": [
    {"severity": "high|medium|low|info", "item": "<发现>", "action": "<建议操作>"}
  ],
  "commands_run": ["<执行的命令>"],
  "changes_made": ["<配置变更记录>"],
  "next_check": "<下次巡检建议时间>",
  "habit_hints": {
    "check_frequency": "daily|weekly",
    "critical_paths": ["<需重点关注的路径>"],
    "preferred_log_sources": ["<常用日志文件>"]
  }
}
```