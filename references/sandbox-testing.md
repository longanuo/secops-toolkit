# 沙盒测试模式：环境搭建与服务器稳定性测试

## 沙盒选型决策树

```
需要完整OS内核隔离？
  YES → KVM/QEMU（完整虚拟化，最高隔离性）
  NO  → 
    需要轻量快速启动？
      YES → Docker容器（适合应用层测试）
      NO  → LXC（系统容器，比Docker更接近真实OS）

测试场景：
  漏洞复现/恶意样本分析    → KVM（强隔离，防逃逸）
  Web应用测试/渗透练习     → Docker
  服务器稳定性压测         → Docker + 资源限制
  大赛靶场环境             → Docker Compose
```

---

## Docker 沙盒快速搭建

### 标准安全沙盒配置
```bash
# 安装Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker $USER

# 创建隔离网络（沙盒专用，不与宿主网段互通）
docker network create \
  --driver bridge \
  --subnet 172.28.0.0/16 \
  --opt "com.docker.network.bridge.enable_ip_masquerade"="true" \
  sandbox-net

# 启动沙盒容器（资源限制 + 网络隔离）
docker run -d \
  --name sandbox-target \
  --network sandbox-net \
  --memory="512m" \
  --cpus="1.0" \
  --pids-limit=100 \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,size=100m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  ubuntu:22.04 sleep infinity
```

### CTF靶机环境 Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  target-web:
    image: webgoat/webgoat:latest  # 可替换为任意靶机镜像
    networks:
      - ctf-net
    ports:
      - "127.0.0.1:8080:8080"     # 仅本地访问
    environment:
      - TZ=Asia/Shanghai
    restart: unless-stopped
    mem_limit: 1g
    cpus: '1'

  attacker:
    image: kalilinux/kali-rolling
    networks:
      - ctf-net
    stdin_open: true
    tty: true
    volumes:
      - ./tools:/opt/tools         # 挂载工具目录
      - ./loot:/opt/loot           # 挂载结果目录

networks:
  ctf-net:
    driver: bridge
    internal: true                  # 完全隔离，无法访问外网

# 启动: docker compose up -d
# 进入攻击机: docker exec -it attacker bash
```

### 一键搭建常见漏洞环境
```bash
# DVWA（PHP漏洞练习）
docker run -d -p 127.0.0.1:8080:80 vulnerables/web-dvwa

# Vulhub（大量真实CVE环境）
git clone https://github.com/vulhub/vulhub
cd vulhub/flask/ssti && docker compose up -d

# Pikachu（中文漏洞练习平台）
docker run -d -p 127.0.0.1:8081:80 area39/pikachu

# HackTheBox本地练习（OpenVPN连接）
openvpn --config your-lab.ovpn
```

---

## 服务器稳定性测试

### 压力测试套件
```bash
# CPU压力测试
apt install stress-ng -y
stress-ng --cpu 4 --timeout 60s --metrics-brief   # 4核心60秒
stress-ng --cpu 4 --cpu-method all --timeout 300s  # 全算法测试

# 内存压力测试
stress-ng --vm 2 --vm-bytes 80% --timeout 60s

# 磁盘I/O测试
# 顺序读写
fio --name=seq_write --ioengine=libaio --direct=1 \
    --rw=write --bs=1M --size=4G --numjobs=1 \
    --filename=/tmp/test_file
# 随机读写（IOPS）
fio --name=rand_rw --ioengine=libaio --direct=1 \
    --rw=randrw --rwmixread=70 --bs=4K --size=1G \
    --numjobs=4 --filename=/tmp/test_file2

# 网络压力测试
apt install iperf3 -y
# 服务端: iperf3 -s
# 客户端: iperf3 -c server_ip -t 30 -P 8  # 8并发流30秒
```

### Web服务并发压测
```bash
# ab (Apache Bench) - 简单快速
ab -n 10000 -c 100 http://127.0.0.1:8080/

# wrk - 现代高性能压测工具
apt install wrk -y
wrk -t4 -c200 -d30s --latency http://127.0.0.1:8080/

# 参数说明：
# -t4: 4个线程
# -c200: 200个并发连接
# -d30s: 持续30秒
# 输出关注: Requests/sec, 99th percentile latency

# siege - 场景测试（URL列表）
siege -c50 -t60S http://127.0.0.1:8080/
```

### 稳定性监控脚本
```bash
#!/bin/bash
# stability_monitor.sh - 压测期间监控

LOG_FILE="/tmp/stability_$(date +%Y%m%d_%H%M).log"
INTERVAL=5  # 每5秒采样

echo "开始稳定性监控，日志: $LOG_FILE"
echo "时间戳,CPU%,内存%,磁盘IO读MB/s,磁盘IO写MB/s,网络收MB/s,网络发MB/s" > $LOG_FILE

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    MEM=$(free | awk '/Mem/{printf "%.1f", $3/$2*100}')
    
    # 磁盘IO（需要iostat）
    DISK=$(iostat -d 1 1 2>/dev/null | awk '/sda/{print $3, $4}')
    
    # 网络IO
    NET=$(cat /proc/net/dev | awk '/eth0/{print $2, $10}')
    
    echo "$TIMESTAMP,$CPU,$MEM,$DISK,$NET" | tee -a $LOG_FILE
    sleep $INTERVAL
done
```

### 网络连接稳定性测试
```bash
# 长时间ping测试（检测丢包）
ping -c 1000 -i 0.5 target_ip | tee ping_test.log
# 分析结果
grep -E "packet loss|rtt" ping_test.log

# MTR（路由追踪+丢包统计）
mtr --report --report-cycles 100 target_ip

# TCP连接稳定性
nc -zv target_ip target_port  # 简单连通性
# 持续测试
for i in {1..100}; do
    nc -w 2 -z target_ip target_port && echo "OK" || echo "FAIL"
    sleep 1
done | grep -c "FAIL"
```

---

## 漏洞复现沙盒流程

### 标准漏洞复现步骤
```
1. 在 sandbox-net 中启动目标容器
2. 确认网络完全隔离（ping 8.8.8.8 应失败）
3. 在攻击容器中执行利用代码
4. 记录成功/失败结果
5. 测试完成后：
   docker compose down --volumes  # 彻底清除
6. 将有效的防御规则同步到 references/firewall-setup.md
```

### 漏洞复现记录模板
```markdown
# CVE-XXXX-XXXX 复现记录

## 环境
- 靶机: [镜像名:版本]
- 工具: [使用的工具]
- 日期: [日期]

## 漏洞原理
[简述]

## 复现步骤
1. [步骤1]
2. [步骤2]

## 影响范围
[受影响版本/配置]

## 检测特征
- 日志特征: [匹配模式]
- 网络特征: [流量特征]
- 文件特征: [文件变化]

## 防御措施
1. 补丁修复: [更新命令]
2. 防火墙规则: [nftables规则]
3. WAF规则: [规则]
4. 监控告警: [日志匹配规则]
```

---

## Hermes Agent 沙盒模式输出
```json
{
  "mode": "sandbox-testing",
  "test_type": "stability|vuln_repro|ctf_env|stress",
  "environment": {
    "type": "docker|kvm|lxc",
    "image": "<镜像名>",
    "network": "isolated|nat",
    "resource_limits": {"cpu": "<限制>", "memory": "<限制>"}
  },
  "test_results": {
    "status": "pass|fail|partial",
    "metrics": {},
    "findings": []
  },
  "artifacts": [{"type": "log|report|config", "path": "<路径>"}],
  "defense_rules_generated": ["<从复现结果提取的防御规则>"],
  "habit_hints": {
    "preferred_sandbox_type": "docker|kvm",
    "typical_test_duration_min": 0,
    "auto_cleanup": true
  }
}
```