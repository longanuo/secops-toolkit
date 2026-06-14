#!/bin/bash
# health_check.sh - 每日巡检脚本

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
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | tail -20
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure | tail -20
else
    journalctl _SYSTEMD_UNIT=ssh.service | grep "Failed" | tail -20
fi

if command -v fail2ban-client &> /dev/null; then
    fail2ban-client status sshd 2>/dev/null
fi

echo "--- 监听端口变化 ---"
ss -tlnp | grep -v "127.0.0.1"

echo "--- 定时任务检查 ---"
crontab -l 2>/dev/null
ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ 2>/dev/null

echo "--- 最近修改的配置文件 (24h内) ---"
find /etc -mtime -1 -type f 2>/dev/null

echo "===== 检查完成 ====="
