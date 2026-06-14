import os
import re
import sys
import platform
import socket
import psutil
from datetime import datetime
from secops_core import utils

def get_system_load():
    """收集CPU、内存、磁盘等基础信息"""
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/') if not utils.is_windows() else psutil.disk_usage('C:\\')
    
    load_info = {
        "hostname": socket.gethostname(),
        "os_type": platform.system(),
        "os_release": platform.platform(),
        "cpu_cores": psutil.cpu_count(logical=True),
        "memory_total": f"{round(mem.total / (1024**3), 1)} GB",
        "memory_used_percent": f"{mem.percent}%",
        "disk_total": f"{round(disk.total / (1024**3), 1)} GB",
        "disk_used_percent": f"{disk.percent}%"
    }

    return load_info

def check_accounts():
    """检测系统中具有特权或多余的账号"""
    results = {
        "uid_zero_users": [],
        "user_count": 0,
        "status": "info",
        "description": ""
    }
    
    if utils.is_windows():
        rc, stdout, stderr = utils.run_cmd("net user", shell=True)
        if rc == 0:
            # 简单统计用户数
            users = [line.strip() for line in stdout.split("\n") if line.strip() and not line.startswith("-") and not line.startswith("User accounts") and not line.startswith("The command")]
            results["user_count"] = len(users)
        results["description"] = "Windows 账号体检仅提供基础用户列表统计"
        return results

    # Linux 下检查 UID=0 账户
    try:
        with open("/etc/passwd", "r") as f:
            lines = f.readlines()
        
        results["user_count"] = len(lines)
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) >= 3:
                username = parts[0]
                uid = parts[2]
                if uid == "0":
                    results["uid_zero_users"].append(username)
        
        if len(results["uid_zero_users"]) > 1:
            results["status"] = "warning"
            results["description"] = f"发现多个 UID=0 的特权用户: {', '.join(results['uid_zero_users'])}"
        else:
            results["status"] = "pass"
            results["description"] = "仅存在默认的 root 特权账号，符合规范"
    except Exception as e:
        results["description"] = f"读取账户文件失败: {str(e)}"
        
    return results

def check_ssh_config():
    """读取 SSH 服务配置文件进行安全指标判断"""
    results = {
        "ssh_installed": False,
        "permit_root_login": "未知",
        "password_authentication": "未知",
        "ssh_port": "未知",
        "status": "info",
        "issues": []
    }
    
    if utils.is_windows():
        results["status"] = "n/a"
        return results
    
    config_path = "/etc/ssh/sshd_config"
    if not os.path.exists(config_path):
        results["status"] = "warning"
        results["issues"].append("未检测到 SSH 配置文件，可能未安装或使用非默认路径")
        return results

    results["ssh_installed"] = True
    
    # 默认值假设
    root_login = "yes"
    pwd_auth = "yes"
    port = "22"
    
    try:
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].lower()
                    val = parts[1].lower()
                    if key == "permitrootlogin":
                        root_login = val
                    elif key == "passwordauthentication":
                        pwd_auth = val
                    elif key == "port":
                        port = val
                        
        results["permit_root_login"] = root_login
        results["password_authentication"] = pwd_auth
        results["ssh_port"] = port
        
        if root_login == "yes":
            results["issues"].append("允许 root 账户直接进行 SSH 登录（安全建议：禁用 PermitRootLogin）")
        if pwd_auth == "yes":
            results["issues"].append("启用了密码认证（安全建议：禁用密码，采用公钥证书登录）")
        if port == "22":
            results["issues"].append("SSH 使用默认端口 22，极易遭受扫描暴破（安全建议：修改默认端口）")
            
        if results["issues"]:
            results["status"] = "warning"
        else:
            results["status"] = "pass"
    except Exception as e:
        results["issues"].append(f"读取 SSH 配置失败: {str(e)}")
        
    return results

def check_services():
    """检测关键加固服务状态 (Linux)"""
    services = ["nftables", "fail2ban", "auditd"]
    results = {}
    
    if utils.is_windows():
        # Windows 检测防火墙配置
        rc, stdout, stderr = utils.run_cmd("netsh advfirewall show allprofiles", shell=True)
        results["windows_firewall"] = "active" if "ON" in stdout else "inactive"
        return results

    for svc in services:
        rc, stdout, stderr = utils.run_cmd(["systemctl", "is-active", svc])
        is_active = stdout.strip() == "active"
        
        rc_enabled, stdout_enabled, stderr_enabled = utils.run_cmd(["systemctl", "is-enabled", svc])
        is_enabled = stdout_enabled.strip() == "enabled"
        
        results[svc] = {
            "active": is_active,
            "enabled": is_enabled
        }
    return results

def check_ports():
    """收集系统当前监听的端口"""
    ports = []
    if utils.is_windows():
        rc, stdout, stderr = utils.run_cmd("netstat -ano", shell=True)
        if rc == 0:
            for line in stdout.split("\n"):
                if "LISTENING" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ports.append(parts[1])
    else:
        # Linux ss 命令
        rc, stdout, stderr = utils.run_cmd(["ss", "-tlnp"])
        if rc == 0:
            lines = stdout.strip().split("\n")
            # 跳过表头
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[3]
                    process_info = parts[5] if len(parts) >= 6 else "未知进程"
                    ports.append(f"{local_addr} ({process_info})")
        else:
            # 降级读取 netstat
            rc, stdout, stderr = utils.run_cmd(["netstat", "-tlnp"])
            if rc == 0:
                lines = stdout.strip().split("\n")
                for line in lines[2:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ports.append(f"{parts[3]} ({parts[6] if len(parts)>=7 else '未知'})")
                        
    return ports[:50] # 截断最多50个端口以防输出过长

def check_windows_policy():
    """检测 Windows 安全策略基线（密码长度、Guest 账户、RDP NLA认证）"""
    results = {
        "status": "pass",
        "description": "Windows 基线检查完成",
        "issues": [],
        "guest_disabled": "未知",
        "min_password_len": "未知",
        "rdp_nla_enabled": "未知",
    }
    
    if not utils.is_windows():
        results["status"] = "n/a"
        return results
        
    # 1. 检查 Guest 状态
    rc, stdout, stderr = utils.run_cmd("net user Guest", shell=True)
    if rc == 0:
        if "No" in stdout or "否" in stdout:
            results["guest_disabled"] = "yes"
        else:
            results["guest_disabled"] = "no"
            results["issues"].append("Guest 账户处于启用状态（安全建议：禁用 Guest 账户）")
            results["status"] = "warning"
            
    # 2. 检查密码最小长度
    rc, stdout, stderr = utils.run_cmd("net accounts", shell=True)
    if rc == 0:
        match = re.search(r"(?:Minimum password length|最小密码长度):\s*(\d+)", stdout)
        if match:
            min_len = int(match.group(1))
            results["min_password_len"] = min_len
            if min_len < 12:
                results["issues"].append(f"密码最小长度为 {min_len} 位，低于基线要求 (安全建议：设置至少 12 位)")
                results["status"] = "warning"
                
    # 3. 检查 RDP 及其 NLA (网络级别身份验证)
    rdp_query = 'Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue'
    rc, stdout, stderr = utils.run_ps_cmd(rdp_query)
    if rc == 0:
        match = re.search(r"UserAuthentication\s*:\s*(\d+)", stdout)
        if match:
            nla_state = match.group(1).strip()
            if nla_state == "1":
                results["rdp_nla_enabled"] = "yes"
            else:
                results["rdp_nla_enabled"] = "no"
                results["issues"].append("远程桌面(RDP)未启用网络级别身份验证(NLA)（安全建议：启用 NLA）")
                results["status"] = "warning"
                
    return results

def check_linux_files():
    """Linux 核心敏感文件权限与登录安全参数审计"""
    results = {
        "status": "pass",
        "issues": [],
        "file_permissions": {},
        "login_defs": {}
    }
    
    if utils.is_windows():
        results["status"] = "n/a"
        return results
        
    # 1. 检测核心文件权限
    files_to_check = {
        "/etc/passwd": 0o644,
        "/etc/shadow": 0o600,
        "/etc/group": 0o644,
        "/etc/gshadow": 0o600
    }
    
    for filepath, max_perm in files_to_check.items():
        if os.path.exists(filepath):
            try:
                stat_val = os.stat(filepath)
                actual_perm = stat_val.st_mode & 0o777
                results["file_permissions"][filepath] = oct(actual_perm)
                if (actual_perm & ~max_perm) != 0:
                    results["issues"].append(f"敏感文件 {filepath} 权限过高: {oct(actual_perm)} (基线建议 <= {oct(max_perm)})")
                    results["status"] = "warning"
            except Exception as e:
                results["issues"].append(f"无法获取 {filepath} 的权限: {str(e)}")
                
    # 2. 检查 /etc/login.defs 参数
    login_defs_path = "/etc/login.defs"
    if os.path.exists(login_defs_path):
        try:
            with open(login_defs_path, "r") as f:
                content = f.read()
            pass_max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.M)
            pass_min_len = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", content, re.M)
            
            if pass_max_days:
                val = int(pass_max_days.group(1))
                results["login_defs"]["PASS_MAX_DAYS"] = val
                if val > 90:
                    results["issues"].append(f"密码最长有效期 PASS_MAX_DAYS 为 {val} 天，超出基线要求 (建议 <= 90天)")
                    results["status"] = "warning"
            if pass_min_len:
                val = int(pass_min_len.group(1))
                results["login_defs"]["PASS_MIN_LEN"] = val
                if val < 12:
                    results["issues"].append(f"密码最小长度 PASS_MIN_LEN 为 {val} 位，低于基线要求 (建议 >= 12位)")
                    results["status"] = "warning"
        except Exception as e:
            results["issues"].append(f"读取 /etc/login.defs 失败: {str(e)}")
            
    return results

def run_evaluation():
    """执行全部体检模块，并评估出综合安全评分"""
    print("[*] 正在分析系统状态信息...")
    load = get_system_load()
    print("[*] 正在扫描特权账户配置...")
    accounts = check_accounts()
    print("[*] 正在扫描系统对外监听端口...")
    ports = check_ports()

    score = 100
    
    if not utils.is_windows():
        print("[*] 正在扫描SSH安全属性...")
        ssh = check_ssh_config()
        print("[*] 正在扫描安全防护守护进程...")
        services = check_services()
        print("[*] 正在进行敏感文件与登录参数审计...")
        linux_files = check_linux_files()
        
        # 1. 账号风险扣分
        if len(accounts.get("uid_zero_users", [])) > 1:
            score -= 20
        # 2. SSH 风险扣分
        if ssh.get("permit_root_login") == "yes":
            score -= 10
        if ssh.get("password_authentication") == "yes":
            score -= 10
        if ssh.get("ssh_port") == "22":
            score -= 5
        # 3. 加固服务未启动扣分
        for svc, state in services.items():
            if isinstance(state, dict) and not state.get("active"):
                score -= 10
        # 4. 文件权限扣分
        if linux_files["status"] == "warning":
            score -= 15
        # 5. login.defs 扣分
        for issue in linux_files["issues"]:
            if "PASS_MAX_DAYS" in issue or "PASS_MIN_LEN" in issue:
                score -= 5
                
        scan_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": max(score, 0),
            "load": load,
            "accounts": accounts,
            "ssh": ssh,
            "services": services,
            "ports": ports,
            "linux_files": linux_files
        }
    else:
        print("[*] 正在扫描 Windows 本地安全策略...")
        services = check_services()
        win_policy = check_windows_policy()
        
        # 1. 防火墙扣分
        if services.get("windows_firewall") != "active":
            score -= 30
        # 2. Guest 账户扣分
        if win_policy.get("guest_disabled") == "no":
            score -= 20
        # 3. 密码长度扣分
        min_len = win_policy.get("min_password_len")
        if isinstance(min_len, int) and min_len < 12:
            score -= 20
        # 4. RDP NLA扣分
        if win_policy.get("rdp_nla_enabled") == "no":
            score -= 15
            
        scan_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": max(score, 0),
            "load": load,
            "accounts": accounts,
            "ssh": {
                "ssh_installed": False,
                "permit_root_login": "n/a",
                "password_authentication": "n/a",
                "ssh_port": "n/a",
                "status": "n/a",
                "issues": []
            },
            "services": services,
            "ports": ports,
            "windows_policy": win_policy
        }

    # 控制台打印简易体检结论
    print(f"\n==========================================")
    print(f"            系统安全体检完成              ")
    print(f"==========================================")
    print(f"主机名称: {load['hostname']}")
    print(f"安全评分: {scan_data['score']} / 100")
    if scan_data['score'] == 100:
        print(f"评估结果: 优秀，暂未发现明显的基线隐患。")
    elif scan_data['score'] >= 80:
        print(f"评估结果: 良好，存在少数几项安全优化空间。")
    elif scan_data['score'] >= 60:
        print(f"评估结果: 一般，请及时应用安全加固策略。")
    else:
        print(f"评估结果: 风险高！存在多项高危隐患，建议立即加固。")
    print(f"==========================================")

    return scan_data

