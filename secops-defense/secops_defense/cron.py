import os
import json
import requests
from datetime import datetime
from secops_core import utils
from secops_defense import evaluator

def get_webhook_url():
    """获取配置的 Webhook URL"""
    url = os.environ.get("SECOPS_WEBHOOK_URL")
    if url:
        return url
        
    # 读配置文件
    conf_dir = "/etc/secops" if not utils.is_windows() else "C:\\Program Files\\SecOps"
    conf_file = os.path.join(conf_dir, "config.json")
    if os.path.exists(conf_file):
        try:
            with open(conf_file, "r", encoding="utf-8") as f:
                config = json.load(f)
                return config.get("webhook_url")
        except:
            pass
    return None

def send_webhook_alert(webhook_url, score, data):
    """通用 Webhook 消息发送，支持 飞书、钉钉、企业微信"""
    if not webhook_url:
        return
        
    hostname = data["load"]["hostname"]
    timestamp = data["timestamp"]
    issues_summary = []
    
    # 提取一些关键问题
    if not utils.is_windows():
        ssh_issues = data.get("ssh", {}).get("issues", [])
        issues_summary.extend(ssh_issues)
        if data.get("linux_files", {}).get("status") == "warning":
            issues_summary.extend(data["linux_files"].get("issues", []))
    else:
        win_issues = data.get("windows_policy", {}).get("issues", [])
        issues_summary.extend(win_issues)
        
    issues_str = "\n".join([f"- {iss}" for iss in issues_summary[:5]])
    if len(issues_summary) > 5:
        issues_str += f"\n- ... 以及其他 {len(issues_summary) - 5} 项隐患"
        
    msg = (
        f"🚨 [SecOps 警报] 服务器安全评分过低！\n"
        f"主机名称: {hostname}\n"
        f"安全评分: {score} / 100\n"
        f"检测时间: {timestamp}\n"
        f"关键基线缺陷:\n{issues_str or '- 无明显的具体基线隐患'}\n"
        f"请立即登录系统执行加固命令: `secops --harden`"
    )
    
    headers = {"Content-Type": "application/json"}
    payload = {}
    
    # 智能解析 Webhook 平台类型
    if "feishu" in webhook_url or "larksuite" in webhook_url:
        payload = {
            "msg_type": "text",
            "content": {
                "text": msg
            }
        }
    elif "dingtalk" in webhook_url or "qyapi.weixin" in webhook_url:
        payload = {
            "msgtype": "text",
            "text": {
                "content": msg
            }
        }
    else:
        # 通用 Webhook 格式
        payload = {
            "text": msg,
            "score": score,
            "hostname": hostname,
            "timestamp": timestamp,
            "issues": issues_summary
        }
        
    try:
        # 配合代理发送 Webhook，提供 5 秒超时
        requests.post(webhook_url, json=payload, headers=headers, timeout=5, proxies=utils.get_proxies())
        print("[*] Webhook 告警消息发送成功。")
    except Exception as e:
        print(f"[!] Webhook 发送失败: {str(e)}")

def setup_cronjob():
    """在 Linux 下配置每日自动巡检与防火墙更新的任务"""
    if utils.is_windows():
        print("[!] Cron 任务仅支持 Linux 环境。")
        return False
        
    if not utils.is_admin():
        print("[!] 写入 Cron 任务需要管理员权限。")
        return False

    cron_file = "/etc/cron.d/secops"
    # 获取 secops 执行路径
    rc, stdout, stderr = utils.run_cmd(["which", "secops"])
    if rc != 0:
        print("[!] 找不到 secops 命令，请确保已通过 pip install -e . 安装。")
        return False
        
    secops_path = stdout.strip()
    
    cron_content = f"""# SecOps 自动化巡检与防护任务
# 每天凌晨 2:00 更新威胁情报并重启防火墙黑名单
0 2 * * * root {secops_path} --update-firewall >> /var/log/secops_firewall.log 2>&1
# 每天凌晨 3:00 执行系统安全体检，若低于75分则触发告警
0 3 * * * root {secops_path} --cron-check >> /var/log/secops_check.log 2>&1
"""
    try:
        with open(cron_file, "w", encoding="utf-8") as f:
            f.write(cron_content)
        utils.run_cmd(["chmod", "644", cron_file])
        print(f"[*] 成功配置定时巡检与防火墙更新任务：{cron_file}")
        return True
    except Exception as e:
        print(f"[!] 配置 Cron 失败: {str(e)}")
        return False

def run_cron_check():
    """定时任务专用的巡检逻辑，支持导出告警并触发多通道 Webhook 告警"""
    print(f"[*] 执行定时巡检... {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    data = evaluator.run_evaluation()
    score = data["score"]
    
    if score < 75:
        print(f"[!] 警告：系统当前安全评分为 {score}，存在高危隐患！")
        
        # 1. 导出本地告警供 Hermes Agent 读取
        alert_file = "/tmp/secops_alerts.json" if not utils.is_windows() else "C:\\Program Files\\SecOps\\secops_alerts.json"
        alert_dir = os.path.dirname(alert_file)
        try:
            os.makedirs(alert_dir, exist_ok=True)
            alert_data = {
                "timestamp": data["timestamp"],
                "score": score,
                "level": "critical",
                "message": "安全评分过低，建议立即执行加固。",
                "details": data
            }
            with open(alert_file, "w", encoding="utf-8") as f:
                json.dump(alert_data, f, ensure_ascii=False, indent=2)
            print(f"[*] 告警数据已写入 {alert_file}。")
        except Exception as e:
            print(f"[!] 写入本地告警文件失败: {str(e)}")
            
        # 2. 触发 Webhook 通道即时报警
        webhook_url = get_webhook_url()
        if webhook_url:
            print("[*] 检测到 Webhook 配置，正在投递即时告警...")
            send_webhook_alert(webhook_url, score, data)
        else:
            print("[*] 未配置 Webhook 地址，跳过网络告警。")
    else:
        print(f"[*] 系统安全评分为 {score}，正常。")

