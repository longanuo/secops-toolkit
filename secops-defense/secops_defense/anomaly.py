"""异常检测模块"""
import os
import re
from datetime import datetime, timedelta
from typing import List, Dict
from secops_core import utils
from secops_defense.ai_tuning import AITuningModule

# Initialize AI tuner singleton
_ai_tuner = AITuningModule()

def report_anomaly_feedback(rule_id: str, is_false_positive: bool):
    """
    User/System feedback loop to mark anomalies as false positive or true positive.
    """
    _ai_tuner.report_feedback(rule_id, is_false_positive)
    print(f"[*] Feedback submitted for rule '{rule_id}' (FP: {is_false_positive})")

def check_failed_logins(log_file: str = "/var/log/auth.log", default_threshold: int = 10, hours: int = 24) -> List[Dict]:
    """
    检测暴力破解登录尝试
    :param log_file: 认证日志文件路径
    :param default_threshold: 默认触发告警的失败次数阈值
    :param hours: 检查最近 N 小时
    :return: 异常登录列表
    """
    # Use AI tuning to adjust threshold dynamically
    threshold = _ai_tuner.tune_threshold("brute_force_login", default_threshold)
    print(f"[*] AI tuned brute_force threshold from {default_threshold} -> {threshold}")
    if utils.is_windows():
        # Windows: 检查安全事件日志
        rc, stdout, stderr = utils.run_cmd("wevtutil qe Security /q:\"*[System[EventID=4625]]\" /c:100 /f:text", shell=True)
        if rc == 0:
            return _parse_windows_failed_logins(stdout, threshold)
        return []

    if not os.path.exists(log_file):
        return []

    anomalies = []
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # 统计失败登录
        failed_attempts = {}
        for line in lines:
            if "Failed password" in line or "authentication failure" in line:
                # 提取 IP
                ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        # 超过阈值的视为异常
        for ip, count in failed_attempts.items():
            if count >= threshold:
                anomalies.append({
                    "type": "brute_force",
                    "ip": ip,
                    "attempts": count,
                    "severity": "critical" if count >= 50 else "high" if count >= 20 else "medium",
                    "description": f"IP {ip} 在日志中尝试登录失败 {count} 次"
                })

    except Exception as e:
        print(f"[!] 读取日志失败: {str(e)}")

    return anomalies


def _parse_windows_failed_logins(output: str, threshold: int) -> List[Dict]:
    """解析 Windows 失败登录事件"""
    anomalies = []

    # 统计来源 IP
    failed_attempts = {}
    ip_pattern = re.compile(r'Source Network Address:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for line in output.split('\n'):
        match = ip_pattern.search(line)
        if match:
            ip = match.group(1)
            if ip != '-' and ip != '127.0.0.1':
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    for ip, count in failed_attempts.items():
        if count >= threshold:
            anomalies.append({
                "type": "brute_force",
                "ip": ip,
                "attempts": count,
                "severity": "critical" if count >= 50 else "high" if count >= 20 else "medium",
                "description": f"IP {ip} 尝试登录失败 {count} 次"
            })

    return anomalies


def check_suspicious_processes() -> List[Dict]:
    """检测可疑进程"""
    anomalies = []

    # 可疑进程特征
    suspicious_patterns = [
        (r'nc\s+-l', "Netcat listener"),
        (r'ncat', "Ncat connection"),
        (r'minergate', "Cryptominer"),
        (r'xmrig', "Cryptominer"),
        (r'kworkerds', "挖矿程序"),
        (r'\./\.hidden', "隐藏文件执行"),
        (r'/tmp/\.', "临时目录隐藏文件"),
        (r'python.*-c.*import.*socket', "Python reverse shell"),
        (r'perl.*-e.*socket', "Perl reverse shell"),
        (r'ruby.*-e.*TCPSocket', "Ruby reverse shell"),
        (r'bash.*-i.*>&.*tcp', "Bash reverse shell"),
    ]

    if utils.is_windows():
        rc, stdout, stderr = utils.run_cmd("tasklist /FO CSV", shell=True)
        if rc == 0:
            for line in stdout.split('\n'):
                for pattern, desc in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        anomalies.append({
                            "type": "suspicious_process",
                            "process": line[:100],
                            "severity": "high",
                            "description": f"检测到可疑进程: {desc}"
                        })
    else:
        rc, stdout, stderr = utils.run_cmd(["ps", "aux"])
        if rc == 0:
            for line in stdout.split('\n'):
                for pattern, desc in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        anomalies.append({
                            "type": "suspicious_process",
                            "process": line[:100],
                            "severity": "high",
                            "description": f"检测到可疑进程: {desc}"
                        })

    return anomalies


def check_unauthorized_keys() -> List[Dict]:
    """检测未授权的 SSH 公钥"""
    anomalies = []

    if utils.is_windows():
        return anomalies

    authorized_keys_paths = [
        "/root/.ssh/authorized_keys",
        "/home/*/authorized_keys",
    ]

    import glob
    for pattern in authorized_keys_paths:
        for path in glob.glob(pattern):
            try:
                with open(path, "r") as f:
                    keys = f.readlines()

                if len(keys) > 5:  # 超过5个公钥视为异常
                    anomalies.append({
                        "type": "unauthorized_keys",
                        "path": path,
                        "count": len(keys),
                        "severity": "medium",
                        "description": f"文件 {path} 包含 {len(keys)} 个公钥，可能存在未授权访问"
                    })
            except Exception:
                pass

    return anomalies


def run_anomaly_detection() -> List[Dict]:
    """运行所有异常检测"""
    all_anomalies = []

    print("[*] 检测暴力破解登录...")
    all_anomalies.extend(check_failed_logins())

    print("[*] 检测可疑进程...")
    all_anomalies.extend(check_suspicious_processes())

    print("[*] 检测未授权 SSH 密钥...")
    all_anomalies.extend(check_unauthorized_keys())

    return all_anomalies
