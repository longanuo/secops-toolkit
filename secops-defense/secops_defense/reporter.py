import os
import sys
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, Template
from secops_core import utils

def get_base_path():
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, "secops")
    return os.path.dirname(__file__)

def generate_reports(scan_data):
    """
    根据体检数据生成HTML与Markdown报告
    :param scan_data: evaluator.run_evaluation() 返回的字典数据
    :return: (html_report_path, md_report_path)
    """
    hostname = scan_data["load"]["hostname"]
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    html_filename = f"secops_report_{hostname}_{timestamp_slug}.html"
    md_filename = f"secops_report_{hostname}_{timestamp_slug}.md"
    
    # 确保保存到执行命令时的当前工作目录
    html_path = os.path.abspath(html_filename)
    md_path = os.path.abspath(md_filename)
    
    # 1. 生成HTML报告
    # 定位模板路径
    template_path = os.path.join(os.path.dirname(__file__), "templates", "report_template.html")
    
    score = scan_data["score"]
    if score >= 80:
        score_class = "score-high"
    elif score >= 60:
        score_class = "score-med"
    else:
        score_class = "score-low"
        
    is_windows = utils.is_windows()
    
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            
        template = Template(template_content)
        html_output = template.render(
            timestamp=scan_data["timestamp"],
            score=score,
            score_class=score_class,
            load=scan_data["load"],
            accounts=scan_data["accounts"],
            ssh=scan_data["ssh"],
            services=scan_data["services"],
            ports=scan_data["ports"],
            is_windows=is_windows
        )
        
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_output)
    except Exception as e:
        # 写入错误占位HTML，防止Crash
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(f"<html><body><h1>报告生成失败</h1><p>{str(e)}</p></body></html>")
            
    # 2. 生成Markdown报告
    md_output = []
    md_output.append(f"# SecOps 服务器安全评估与加固成果报告")
    md_output.append(f"**报告生成时间**: {scan_data['timestamp']}\n")
    md_output.append(f"## 1. 综合安全评分: {score} / 100")
    if score == 100:
        md_output.append("评估结论: 优秀。系统符合所有常规配置基线标准。\n")
    elif score >= 80:
        md_output.append("评估结论: 良好。系统整体较安全，但有少数优化建议。\n")
    elif score >= 60:
        md_output.append("评估结论: 一般。系统暴露了若干项中高危隐患，需要执行加固措施。\n")
    else:
        md_output.append("评估结论: 风险高！系统存在严重的安全基线缺陷，极易遭受自动化扫描和暴破攻击，应立刻应用安全加固。\n")
        
    md_output.append("## 2. 系统基础状态信息")
    md_output.append(f"- **主机名称**: {scan_data['load']['hostname']}")
    md_output.append(f"- **操作系统**: {scan_data['load']['os_type']} ({scan_data['load']['os_release']})")
    md_output.append(f"- **CPU核心**: {scan_data['load']['cpu_cores']} 核")
    md_output.append(f"- **内存大小/使用率**: {scan_data['load']['memory_total']} (当前: {scan_data['load']['memory_used_percent']})")
    md_output.append(f"- **系统磁盘/使用率**: {scan_data['load']['disk_total']} (当前: {scan_data['load']['disk_used_percent']})\n")
    
    md_output.append("## 3. 安全基线指标比对表")
    if not is_windows:
        ssh_data = scan_data["ssh"]
        accounts_data = scan_data["accounts"]
        svc_data = scan_data["services"]
        
        md_output.append("| 检查项 | 目标基线标准 | 当前系统状态 | 结论 |")
        md_output.append("| --- | --- | --- | --- |")
        
        root_login_ok = "符合" if ssh_data.get("permit_root_login") == "no" else "不符合 (允许)"
        md_output.append(f"| SSH Root 登录 | 禁止登录 (no) | {ssh_data.get('permit_root_login')} | {root_login_ok} |")
        
        pwd_auth_ok = "符合" if ssh_data.get("password_authentication") == "no" else "不符合 (启用)"
        md_output.append(f"| SSH 密码认证 | 禁用密码 (no) | {ssh_data.get('password_authentication')} | {pwd_auth_ok} |")
        
        port_ok = "符合" if ssh_data.get("ssh_port") != "22" else "不符合 (默认22)"
        md_output.append(f"| SSH 端口 | 非常规高端口 | {ssh_data.get('ssh_port')} | {port_ok} |")
        
        uid_zero_ok = "安全" if len(accounts_data.get("uid_zero_users", [])) == 1 else "有隐患"
        md_output.append(f"| 特权账户检测 | 仅存在默认 root | UID=0 用户数: {len(accounts_data.get('uid_zero_users', []))} | {uid_zero_ok} |")
        
        nft_ok = "已启用" if svc_data.get("nftables", {}).get("active") else "未启用"
        md_output.append(f"| nftables 防火墙 | 服务处于活跃运行状态 | {'运行中' if svc_data.get('nftables', {}).get('active') else '未运行'} | {nft_ok} |")
        
        f2b_ok = "已启用" if svc_data.get("fail2ban", {}).get("active") else "未启用"
        md_output.append(f"| fail2ban 防暴破 | 服务处于活跃运行状态 | {'运行中' if svc_data.get('fail2ban', {}).get('active') else '未运行'} | {f2b_ok} |")
        
        aud_ok = "已启用" if svc_data.get("auditd", {}).get("active") else "未启用"
        md_output.append(f"| auditd 系统审计 | 服务处于活跃运行状态 | {'运行中' if svc_data.get('auditd', {}).get('active') else '未运行'} | {aud_ok} |")
    else:
        fw_state = scan_data["services"].get("windows_firewall")
        md_output.append("| 检查项 | 目标基线标准 | 当前系统状态 | 结论 |")
        md_output.append("| --- | --- | --- | --- |")
        fw_ok = "符合" if fw_state == "active" else "不符合"
        md_output.append(f"| 本地防火墙 | 开启 (ON) | {fw_state} | {fw_ok} |")
        
    md_output.append("\n## 4. 监听端口状态")
    for port in scan_data["ports"]:
        md_output.append(f"- `{port}`")
    if not scan_data["ports"]:
        md_output.append("- 无活动对外开放端口")
        
    md_output.append("\n## 5. 安全加固建议")
    if score == 100:
        md_output.append("- 所有基线指标处于符合状态，暂无加固建议。")
    else:
        if not is_windows:
            ssh_data = scan_data["ssh"]
            svc_data = scan_data["services"]
            if ssh_data.get("permit_root_login") == "yes":
                md_output.append("- **[高危] 禁用 SSH Root 直接登录**: 编辑 `/etc/ssh/sshd_config` 设置 `PermitRootLogin no`。")
            if ssh_data.get("password_authentication") == "yes":
                md_output.append("- **[高危] 禁用密码认证**: 设置 `PasswordAuthentication no` 并使用密钥证书登录。")
            if ssh_data.get("ssh_port") == "22":
                md_output.append("- **[中危] 更换默认 SSH 端口**: 修改默认 22 端口为其他高位随机端口，防范自动化扫描。")
            if not svc_data.get("nftables", {}).get("active"):
                md_output.append("- **[高危] 开启 nftables 防火墙**: 启用防火墙访问控制。")
            if not svc_data.get("fail2ban", {}).get("active"):
                md_output.append("- **[中危] 部署 fail2ban**: 防止 SSH 等服务遭受暴力密码破解。")
            if not svc_data.get("auditd", {}).get("active"):
                md_output.append("- **[低危] 启动 auditd**: 对文件修改、特权执行等敏感事件进行系统级审计。")
        else:
            if fw_state != "active":
                md_output.append("- **[高危] 开启 Windows 防火墙**: 运行命令 `netsh advfirewall set allprofiles state on`。")
                
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_output))
        
    return html_path, md_path
