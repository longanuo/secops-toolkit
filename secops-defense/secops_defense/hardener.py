import os
import re
from datetime import datetime
from secops_core import utils

# 全局备份注册表，记录加固时修改的文件
BACKUP_REGISTRY = []

def backup_file(filepath):
    """备份指定的文件，加上时间戳"""
    if os.path.exists(filepath):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{filepath}.bak_{timestamp}"
        try:
            with open(filepath, "r", errors="ignore") as src:
                content = src.read()
            with open(backup_path, "w") as dst:
                dst.write(content)
            # 注册到备份列表
            BACKUP_REGISTRY.append((filepath, backup_path))
            return True, backup_path
        except Exception as e:
            return False, str(e)
    return False, "文件不存在"

def harden_ssh():
    """修改 sshd_config 配置并重启 SSH"""
    config_path = "/etc/ssh/sshd_config"
    if not os.path.exists(config_path):
        return False, "未找到 /etc/ssh/sshd_config 配置文件"

    # 1. 备份
    ok, backup_path = backup_file(config_path)
    if not ok:
        return False, f"备份配置文件失败: {backup_path}"

    # 2. 读取并修改
    try:
        with open(config_path, "r") as f:
            lines = f.readlines()

        new_lines = []
        # 定义要设置的参数映射
        ssh_params = {
            "permitrootlogin": "PermitRootLogin no",
            "passwordauthentication": "PasswordAuthentication no"
        }
        seen = set()

        for line in lines:
            line_stripped = line.strip()
            # 忽略空行
            if not line_stripped:
                new_lines.append(line)
                continue

            # 匹配配置行的 key
            # 可能是：#PermitRootLogin yes 或 PermitRootLogin yes
            match = re.match(r"^#?\s*([a-zA-Z0-9_]+)\s+(.+)$", line_stripped)
            if match:
                key = match.group(1).lower()
                if key in ssh_params:
                    new_lines.append(ssh_params[key] + "\n")
                    seen.add(key)
                    continue
            new_lines.append(line)

        # 把缺失的参数补在末尾
        for key, value in ssh_params.items():
            if key not in seen:
                new_lines.append(value + "\n")

        with open(config_path, "w") as f:
            f.writelines(new_lines)

        # 执行 sshd -t 语法预检
        print("[*] 正在执行 SSH 配置文件语法预检...")
        check_rc, check_out, check_err = utils.run_cmd(["sshd", "-t"])
        if check_rc != 0:
            # 预检失败，回滚
            print(f"[!] 语法预检失败。错误信息: {check_err or check_out}。正在自动回滚 SSH 配置...")
            with open(config_path, "w") as f:
                with open(backup_path, "r", errors="ignore") as src:
                    f.write(src.read())
            return False, "SSH 配置语法预检失败，配置已自动回滚"

        print("[+] SSH 配置文件语法预检通过！")

        # 3. 重启 SSH 服务
        rc, stdout, stderr = utils.run_cmd(["systemctl", "restart", "sshd"])
        if rc != 0:
            utils.run_cmd(["service", "ssh", "restart"])
            
        return True, "SSH 已配置禁用 root 登录与密码登录"
    except Exception as e:
        # 异常情况下也回退
        if os.path.exists(backup_path):
            try:
                with open(config_path, "w") as f:
                    with open(backup_path, "r", errors="ignore") as src:
                        f.write(src.read())
            except Exception:
                pass
        return False, f"修改 SSH 配置文件出错: {str(e)}，已尝试自动回滚"

def install_hardening_packages():
    """使用 apt 安装安全相关的基础包 (libpam-pwquality, fail2ban, auditd)"""
    print("[*] 正在安装基础安全加固软件包 (apt)...")
    # 更新包列表并安装
    rc, stdout, stderr = utils.run_cmd(["apt-get", "update", "-y"])
    rc, stdout, stderr = utils.run_cmd(["apt-get", "install", "-y", "libpam-pwquality", "fail2ban", "auditd"])
    if rc == 0:
        return True, "安全加固包安装成功"
    return False, f"包安装失败: {stderr}"

def harden_password_policy():
    """配置密码复杂度限制"""
    conf_path = "/etc/security/pwquality.conf"
    # 确保父目录存在
    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    
    backup_file(conf_path)
    
    config_content = """# SecOps 自动配置密码复杂度
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
"""
    try:
        with open(conf_path, "w") as f:
            f.write(config_content)
        return True, "已强制设置最小12位且必须包含大小写、数字及特殊字符"
    except Exception as e:
        return False, str(e)

def harden_sysctl():
    """加固系统内核安全参数"""
    conf_path = "/etc/sysctl.d/99-secops-security.conf"
    
    config_content = """# SecOps 自动内核安全加固
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
"""
    try:
        with open(conf_path, "w") as f:
            f.write(config_content)
        # 加载配置
        rc, stdout, stderr = utils.run_cmd(["sysctl", "-p", conf_path])
        if rc == 0:
            return True, "已成功应用并启用内核防御参数 (DDoS防护、内存地址保护)"
        return False, f"加载内核配置失败: {stderr}"
    except Exception as e:
        return False, str(e)

def configure_fail2ban():
    """配置并启动 fail2ban"""
    jail_local_path = "/etc/fail2ban/jail.local"
    
    config_content = """[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
"""
    try:
        with open(jail_local_path, "w") as f:
            f.write(config_content)
        
        # 启用并重启服务
        utils.run_cmd(["systemctl", "enable", "fail2ban"])
        rc, stdout, stderr = utils.run_cmd(["systemctl", "restart", "fail2ban"])
        if rc == 0:
            return True, "fail2ban 服务配置并启动成功，已启用 SSH 登录防暴破"
        return False, f"fail2ban 启动失败: {stderr}"
    except Exception as e:
        return False, str(e)

def configure_auditd():
    """配置并启动 auditd"""
    rules_path = "/etc/audit/rules.d/secops.rules"
    
    rules = """# SecOps 审计规则
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
"""
    try:
        with open(rules_path, "w") as f:
            f.write(rules)
            
        utils.run_cmd(["systemctl", "enable", "auditd"])
        rc, stdout, stderr = utils.run_cmd(["service", "auditd", "restart"])
        if rc == 0:
            return True, "auditd 核心事件监控配置成功"
        return False, f"auditd 启动失败: {stderr}"
    except Exception as e:
        return False, str(e)

def install_crowdsec():
    """自动化安装配置 CrowdSec"""
    print("[*] 正在安装 CrowdSec 及其防火墙 Bouncer...")
    # 自动添加仓库并安装
    setup_cmd = "curl -s https://install.crowdsec.net | sudo sh"
    rc, stdout, stderr = utils.run_cmd(["bash", "-c", setup_cmd])
    if rc != 0:
        return False, f"添加 CrowdSec 仓库失败: {stderr}"
        
    rc, stdout, stderr = utils.run_cmd(["apt-get", "install", "-y", "crowdsec", "crowdsec-firewall-bouncer-iptables"])
    if rc == 0:
        utils.run_cmd(["systemctl", "enable", "crowdsec"])
        utils.run_cmd(["systemctl", "start", "crowdsec"])
        return True, "CrowdSec 及 IPTables Bouncer 安装成功，防御引擎已启动"
    return False, f"CrowdSec 安装失败: {stderr}"

def generate_linux_rollback_script():
    """生成 Linux 下的加退脚本"""
    if not BACKUP_REGISTRY:
        return
    
    rollback_dir = "/opt/cybersec/bin"
    try:
        os.makedirs(rollback_dir, exist_ok=True)
        rollback_script = os.path.join(rollback_dir, "rollback_secops.sh")
        
        script_content = [
            "#!/bin/bash",
            "# SecOps 自动化加固回退脚本",
            "echo '正在恢复安全配置到加固前状态...'"
        ]
        
        for orig, bak in BACKUP_REGISTRY:
            script_content.append(f"cp -p {bak} {orig}")
            
        script_content.append("echo '配置已恢复，请重启相关服务（如 sshd, fail2ban 等）以使改动生效。'")
        
        with open(rollback_script, "w", encoding="utf-8") as f:
            f.write("\n".join(script_content))
        
        # 赋予执行权限
        utils.run_cmd(["chmod", "+x", rollback_script])
        print(f"[*] 已成功在本地生成加固一键回退脚本: {rollback_script}")
    except Exception as e:
        print(f"[!] 无法写入回退脚本: {str(e)}")

def run_windows_hardening():
    """Windows 一键加固逻辑"""
    print("[*] 开始 Windows 安全基线加固流程...")
    
    # 记录原始配置用于回滚
    rollback_cmds = []
    
    # 1. 加固 Guest 账户
    rc, stdout, stderr = utils.run_cmd("net user Guest", shell=True)
    if rc == 0:
        is_active = not ("No" in stdout or "否" in stdout)
        if is_active:
            print("[*] 正在禁用 Guest 账户...")
            set_rc, _, set_err = utils.run_cmd("net user Guest /active:no", shell=True)
            if set_rc == 0:
                print(" -> 成功禁用 Guest 账户")
                rollback_cmds.append("net user Guest /active:yes")
            else:
                print(f" -> 禁用 Guest 账户失败: {set_err}")
        else:
            print(" -> Guest 账户已是禁用状态，无需加固")
            
    # 2. 密码最小长度限制为 12 位
    rc, stdout, stderr = utils.run_cmd("net accounts", shell=True)
    if rc == 0:
        match = re.search(r"(?:Minimum password length|最小密码长度):\s*(\d+)", stdout)
        if match:
            orig_len = int(match.group(1))
            if orig_len < 12:
                print(f"[*] 正在将密码最小长度由 {orig_len} 修改为 12...")
                set_rc, _, set_err = utils.run_cmd("net accounts /minpwlen:12", shell=True)
                if set_rc == 0:
                    print(" -> 密码最小长度加固成功")
                    rollback_cmds.append(f"net accounts /minpwlen:{orig_len}")
                else:
                    print(f" -> 密码长度修改失败: {set_err}")
            else:
                print(f" -> 密码最小长度已符合要求 ({orig_len}位)")
                
    # 3. 启用 RDP NLA
    rdp_query = 'Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue'
    rc, stdout, stderr = utils.run_ps_cmd(rdp_query)
    orig_nla = "1"
    if rc == 0:
        match = re.search(r"UserAuthentication\s*:\s*(\d+)", stdout)
        if match:
            orig_nla = match.group(1).strip()
            
    if orig_nla != "1":
        print("[*] 正在启用 RDP 网络级别身份验证(NLA)...")
        set_cmd = 'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1'
        set_rc, _, set_err = utils.run_ps_cmd(set_cmd)
        if set_rc == 0:
            print(" -> RDP NLA 启用成功")
            rollback_cmds.append(f'Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value {orig_nla}')
        else:
            print(f" -> RDP NLA 启用失败: {set_err}")
    else:
        print(" -> RDP NLA 已是启用状态")
        
    # 4. 开启 Windows Defender 防火墙
    rc, stdout, stderr = utils.run_cmd("netsh advfirewall show allprofiles", shell=True)
    if "OFF" in stdout or "关闭" in stdout:
        print("[*] 正在启用 Windows Defender 防火墙...")
        set_rc, _, set_err = utils.run_cmd("netsh advfirewall set allprofiles state on", shell=True)
        if set_rc == 0:
            print(" -> 防火墙已成功开启")
            rollback_cmds.append("netsh advfirewall set allprofiles state off")
        else:
            print(f" -> 防火墙开启失败: {set_err}")
    else:
        print(" -> Windows 防火墙已处于活动状态")

    # 5. 生成 Windows 回滚脚本
    if rollback_cmds:
        rollback_dir = "C:\\Program Files\\SecOps"
        try:
            os.makedirs(rollback_dir, exist_ok=True)
            rollback_script = os.path.join(rollback_dir, "rollback_secops.ps1")
            
            ps_content = [
                "# Windows SecOps 自动加固回退脚本",
                "Write-Host '正在恢复 Windows 安全加固前的原始配置...'",
                "# 需要管理员权限执行"
            ]
            for cmd in rollback_cmds:
                if cmd.startswith("Set-ItemProperty"):
                    ps_content.append(cmd)
                else:
                    ps_content.append(f'cmd.exe /c "{cmd}"')
            ps_content.append("Write-Host '配置恢复完成。'")
            
            with open(rollback_script, "w", encoding="utf-8") as f:
                f.write("\n".join(ps_content))
            print(f"[*] 已生成一键回退脚本：{rollback_script}")
        except Exception as e:
            print(f"[!] 无法写入回退脚本：{str(e)}")
            
    print("[*] Windows 安全加固完毕！")
    return True

def run_hardening():
    """一键安全加固执行流"""
    if utils.is_windows():
        return run_windows_hardening()

    print("[*] 开始系统安全加固流程...")
    
    # 1. 安装软件包
    ok, msg = install_hardening_packages()
    print(f" -> {msg}")
    
    # 2. SSH 加固
    ok, msg = harden_ssh()
    print(f" -> {msg}")
    
    # 3. 密码策略
    ok, msg = harden_password_policy()
    print(f" -> {msg}")
    
    # 4. 内核加固
    ok, msg = harden_sysctl()
    print(f" -> {msg}")
    
    # 5. 防爆破
    ok, msg = configure_fail2ban()
    print(f" -> {msg}")
    
    # 6. 系统审计
    ok, msg = configure_auditd()
    print(f" -> {msg}")
    
    # 7. CrowdSec 集成
    ok, msg = install_crowdsec()
    print(f" -> {msg}")
    
    # 8. 生成回滚脚本
    generate_linux_rollback_script()
    
    print("[*] 安全加固配置写入完毕！")
    return True

