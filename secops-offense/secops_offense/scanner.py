import json
import os
import tempfile
from secops_core import utils

def run_nuclei_scan(target_url):
    """
    执行 nuclei 漏洞扫描
    :param target_url: 目标 URL
    :return: 发现的漏洞列表，或者如果未安装 nuclei 返回 None
    """
    rc, stdout, stderr = utils.run_cmd(["which", "nuclei"])
    if rc != 0:
        return None
        
    print(f"[*] 正在调用 nuclei 对 {target_url} 进行应用层漏洞扫描 (high,critical)...")
    
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_file = tf.name
        
    rc, stdout, stderr = utils.run_cmd(["nuclei", "-target", target_url, "-severity", "high,critical", "-json-export", out_file])
    
    findings = []
    if os.path.exists(out_file):
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        info = data.get("info", {})
                        findings.append({
                            "id": data.get("template-id", "unknown"),
                            "name": info.get("name", "Unknown vulnerability"),
                            "severity": info.get("severity", "high"),
                            "host": data.get("host", target_url)
                        })
        except:
            pass
        os.remove(out_file)
        
    return findings
