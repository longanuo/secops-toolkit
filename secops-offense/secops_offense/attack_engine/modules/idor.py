"""IDOR 漏洞检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class IDORDetector(BaseDetector):
    """IDOR (不安全的直接对象引用) 漏洞检测器"""

    name = "idor"
    category = "IDOR"

    # 常见 ID 参数
    ID_PARAMS = [
        "id", "user_id", "userid", "uid", "account",
        "profile", "doc", "file", "order", "invoice",
        "page", "item", "record", "key", "ref"
    ]

    # 递增/递减测试值
    ID_PAYLOADS = [
        ("1", "2"), ("100", "101"), ("1000", "1001"),
        ("0", "1"), ("10", "20"),
    ]

    def _extract_id_params(self, url):
        """从 URL 中提取 ID 参数"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        id_params = []
        for key, value in params.items():
            if any(id_param in key.lower() for id_param in self.ID_PARAMS):
                id_params.append((key, value[0] if value else ''))
        return id_params

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 从 URL 参数中提取 ID
        id_params = self._extract_id_params(target_url)

        # 如果没有指定参数，使用默认的 ID 参数列表
        if not id_params and params:
            id_params = [(p, '') for p in params if any(id in p.lower() for id in self.ID_PARAMS)]

        if not id_params:
            # 尝试常见参数
            for param in self.ID_PARAMS:
                test_url = f"{base_url}?{param}=1"
                status, _, body = http_get(test_url, timeout=5)
                if status == 200 and body:
                    id_params.append((param, '1'))
                time.sleep(ATTACK_DELAY)

        # 测试 IDOR 漏洞
        for param, original_value in id_params:
            for val1, val2 in self.ID_PAYLOADS:
                if original_value and original_value != val1:
                    continue

                # 构造两个不同的 ID 请求
                url1 = f"{base_url}?{param}={val1}"
                url2 = f"{base_url}?{param}={val2}"

                log_audit("IDOR_TEST", url1, f"param={param}, comparing {val1} vs {val2}")

                status1, _, body1 = http_get(url1, timeout=8)
                time.sleep(0.2)
                status2, _, body2 = http_get(url2, timeout=8)

                if status1 == 0 or status2 == 0:
                    continue

                # 检查响应是否不同（说明可遍历）
                if status1 == 200 and status2 == 200:
                    if body1 != body2 and len(body1) > 100 and len(body2) > 100:
                        # 检查是否有错误信息泄露
                        error_patterns = [
                            r"not found", r"不存在", r"无权访问",
                            r"unauthorized", r"forbidden", r"denied"
                        ]
                        has_error = any(re.search(p, body2, re.IGNORECASE) for p in error_patterns)

                        if not has_error:
                            findings.append(Finding(
                                vuln_type="IDOR", severity="high",
                                title=f"IDOR 漏洞 - 参数 {param}",
                                location=url2, payload=f"{param}={val2}",
                                evidence=f"修改 {param} 从 {val1} 到 {val2} 返回不同内容，可遍历其他用户数据",
                                description=f"参数 {param} 存在 IDOR 漏洞，攻击者可通过修改 ID 值访问其他用户数据。",
                                remediation="实施访问控制检查，确保用户只能访问自己的数据"
                            ))
                            break

                time.sleep(ATTACK_DELAY)

        return findings
