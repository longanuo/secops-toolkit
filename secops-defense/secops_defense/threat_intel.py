"""威胁情报增强模块"""
import os
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict
from secops_core import utils


# 内置威胁情报源
THREAT_INTEL_SOURCES = {
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "blocklist": "https://lists.blocklist.de/lists/all.txt",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "binarydefense": "https://www.binarydefense.com/banlist.txt",
    "cinsscore": "https://cinsscore.com/list/ci-badguys.txt",
    "emergingthreats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
}

# 恶意 IP 信誉等级
REPUTATION_LEVELS = {
    "critical": {"min_score": 8, "color": "red"},
    "high": {"min_score": 5, "color": "orange"},
    "medium": {"min_score": 3, "color": "yellow"},
    "low": {"min_score": 1, "color": "green"},
}


def fetch_ip_threat_intel(limit=1000) -> List[Dict]:
    """
    从多个源获取恶意 IP 情报
    :param limit: 最大获取数量
    :return: 威胁情报列表
    """
    import requests

    all_ips = {}

    for source_name, url in THREAT_INTEL_SOURCES.items():
        try:
            print(f"[*] 正在从 {source_name} 获取威胁情报...")
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                lines = response.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # 提取 IP
                    ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in all_ips:
                            all_ips[ip] = {"sources": [], "score": 0}
                        all_ips[ip]["sources"].append(source_name)
                        all_ips[ip]["score"] += 1

                ip_count = len([l for l in lines if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', l.strip())])
                print(f"    从 {source_name} 获取了 {ip_count} 条记录")
        except Exception as e:
            print(f"[!] 从 {source_name} 获取失败: {str(e)}")

    # 按信誉分数排序
    sorted_ips = sorted(all_ips.items(), key=lambda x: x[1]["score"], reverse=True)

    return [
        {
            "ip": ip,
            "score": data["score"],
            "sources": data["sources"],
            "reputation": _get_reputation(data["score"])
        }
        for ip, data in sorted_ips[:limit]
    ]


def _get_reputation(score: int) -> str:
    """根据分数获取信誉等级"""
    if score >= 8:
        return "critical"
    elif score >= 5:
        return "high"
    elif score >= 3:
        return "medium"
    else:
        return "low"


def save_threat_intel(ip_list: List[Dict], output_dir: str = None):
    """保存威胁情报到本地"""
    if output_dir is None:
        output_dir = "/opt/cybersec/intel" if not utils.is_windows() else "C:\\Program Files\\SecOps\\intel"

    os.makedirs(output_dir, exist_ok=True)

    # 保存为 JSON
    json_path = os.path.join(output_dir, "threat_intel.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(ip_list, f, ensure_ascii=False, indent=2)

    # 保存为文本
    txt_path = os.path.join(output_dir, "blocked_ips.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        for item in ip_list:
            f.write(f"{item['ip']}\n")

    print(f"[*] 威胁情报已保存到 {output_dir}")
    return json_path, txt_path


def load_local_threat_intel(intel_dir: str = None) -> List[Dict]:
    """加载本地威胁情报"""
    if intel_dir is None:
        intel_dir = "/opt/cybersec/intel" if not utils.is_windows() else "C:\\Program Files\\SecOps\\intel"

    json_path = os.path.join(intel_dir, "threat_intel.json")

    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    return []


def get_threat_summary() -> Dict:
    """获取威胁情报摘要"""
    intel_list = load_local_threat_intel()

    summary = {
        "total": len(intel_list),
        "critical": len([i for i in intel_list if i.get("reputation") == "critical"]),
        "high": len([i for i in intel_list if i.get("reputation") == "high"]),
        "medium": len([i for i in intel_list if i.get("reputation") == "medium"]),
        "low": len([i for i in intel_list if i.get("reputation") == "low"]),
        "last_update": None,
    }

    # 获取最后更新时间
    if intel_list:
        json_path = "/opt/cybersec/intel/threat_intel.json" if not utils.is_windows() else "C:\\Program Files\\SecOps\\intel\\threat_intel.json"
        if os.path.exists(json_path):
            mtime = os.path.getmtime(json_path)
            summary["last_update"] = datetime.fromtimestamp(mtime).isoformat()

    return summary
