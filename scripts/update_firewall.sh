#!/bin/bash
# update_firewall.sh - 供cron定时执行的防火墙更新包装脚本

LOG_FILE="/var/log/secops_firewall_update.log"

echo "=== 开始防火墙情报同步 $(date) ===" >> $LOG_FILE

# 检查secops命令是否在PATH中
if command -v secops &> /dev/null; then
    secops --update-firewall >> $LOG_FILE 2>&1
else
    # 尝试使用python调用模块
    python3 -m secops.cli --update-firewall >> $LOG_FILE 2>&1
fi

if [ $? -eq 0 ]; then
    echo "=== 防火墙更新成功 $(date) ===" >> $LOG_FILE
else
    echo "=== 防火墙更新失败 $(date) ===" >> $LOG_FILE
fi
