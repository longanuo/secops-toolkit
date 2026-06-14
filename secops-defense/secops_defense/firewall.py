import os
import tempfile
from secops_core import utils
from secops_defense import github_intel

# 内置 Fallback IP 列表，用于完全断网且本地无备份时的兜底防护
FALLBACK_IPS = [
    "185.220.101.5",
    "185.220.101.7",
    "45.143.203.14",
    "85.248.227.165",
    "103.145.12.181"
]

def update_threat_intel_firewall():
    """
    拉取恶意IP并原子加载到防火墙中，支持 Windows (通过高级安全防火墙) 和 Linux (通过 nftables)
    :return: True/False
    """
    # 1. 获取恶意 IP 列表 (提供限制)
    ips = []
    try:
        ips = github_intel.fetch_malicious_ips(limit=500)
    except Exception as e:
        print(f"[!] 拉取在线情报发生异常: {str(e)}，将尝试加载本地缓存或兜底数据。")

    # 2. 如果在线拉取失败，尝试从本地缓存加载
    intel_dir = "/opt/cybersec/intel/ips" if not utils.is_windows() else "C:\\Program Files\\SecOps"
    intel_file = os.path.join(intel_dir, "combined.txt")
    
    if not ips:
        if os.path.exists(intel_file):
            print(f"[*] 正在尝试加载本地历史威胁情报缓存: {intel_file}")
            try:
                with open(intel_file, "r", encoding="utf-8") as f:
                    ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                print(f"[+] 成功从本地缓存恢复了 {len(ips)} 条恶意 IP 记录。")
            except Exception as e:
                print(f"[!] 读取本地缓存失败: {str(e)}")
        
        # 3. 如果本地缓存依然为空，采用硬编码 Fallback 兜底
        if not ips:
            print("[*] 无本地缓存，正在应用内置兜底威胁 IP 列表。")
            ips = FALLBACK_IPS

    # 备份到本地（如果可以写入）
    try:
        os.makedirs(intel_dir, exist_ok=True)
        with open(intel_file, "w", encoding="utf-8") as f:
            for ip in ips:
                f.write(ip + "\n")
        print(f"[*] 威胁情报数据已备份缓存至本地: {intel_file}")
    except Exception as e:
        print(f"[!] 无法写入持久化目录: {str(e)}。将仅在内存中执行重载。")

    # 4. 根据平台执行防火墙原子加载
    if utils.is_windows():
        return update_windows_firewall_rules(ips)
    else:
        return update_linux_nftables(ips)

def update_linux_nftables(ips):
    """Linux nftables 原子重载规则"""
    # 检查 nft 命令行工具
    rc, stdout, stderr = utils.run_cmd(["which", "nft"])
    if rc != 0:
        print("[!] 检查失败，当前系统似乎未安装 nftables 防火墙。")
        return False

    # 生成临时 nftables 规则文件用于原子重载
    nft_script = []
    nft_script.append("table inet main {")
    nft_script.append("    set blocked_ips {")
    nft_script.append("        type ipv4_addr")
    nft_script.append("        flags interval")
    nft_script.append("        auto-merge")
    nft_script.append("        elements = {")
    
    for ip in ips:
        nft_script.append(f"            {ip},")
        
    nft_script.append("        }")
    nft_script.append("    }")
    nft_script.append("}")
    
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False, encoding="utf-8") as temp_f:
            temp_f.write("\n".join(nft_script))
            temp_path = temp_f.name
            
        print("[*] 正在执行 nftables 规则原子重载...")
        check_rc, _, _ = utils.run_cmd(["nft", "list", "table", "inet", "main"])
        if check_rc != 0:
            print("[*] 检测到 inet main 表未创建，正在执行初始化表结构...")
            utils.run_cmd(["nft", "add", "table", "inet", "main"])
            utils.run_cmd(["nft", "add", "chain", "inet", "main", "input", "{ type filter hook input priority 0; policy accept; }"])
            
        reload_rc, reload_out, reload_err = utils.run_cmd(["nft", "-f", temp_path])
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        if reload_rc == 0:
            print(f"[*] 成功向 nftables 动态注入了 {len(ips)} 个封禁 IP 节点。")
            return True
        else:
            print(f"[!] nftables 加载临时规则失败: {reload_err}")
            return False
            
    except Exception as e:
        print(f"[!] 防火墙原子更新期间发生异常: {str(e)}")
        return False

def update_windows_firewall_rules(ips):
    """Windows 本地防火墙规则批量更新 (封禁恶意IP)"""
    print("[*] 正在更新 Windows Defender 防火墙恶意 IP 封禁规则...")
    rule_name = "SecOps-Block-Malicious-IPs"
    
    # 1. 先删除旧的规则，防止无限堆积
    del_cmd = f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
    utils.run_ps_cmd(del_cmd)
    
    # 2. 将 IP 数组转换为逗号分隔字符串
    ip_str = ",".join(ips)
    
    # 3. 创建新的 Block 规则
    add_cmd = f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Inbound -Action Block -RemoteAddress {ip_str} -Description 'SecOps 自动拉取的威胁情报封禁名单'"
    rc, stdout, stderr = utils.run_ps_cmd(add_cmd)
    
    if rc == 0:
        print(f"[+] 成功创建 Windows 防火墙封禁规则，已封禁 {len(ips)} 个恶意 IP 节点。")
        return True
    else:
        print(f"[!] 创建 Windows 防火墙规则失败: {stderr}")
        return False
