"""攻击报告生成器"""
import os
import sys
from datetime import datetime
from secops_core.config import REPORT_DIR
from secops_core.logger import get_logger

log = get_logger("offense_reporter")


def get_base_path():
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, "secops_offense")
    return os.path.dirname(__file__)


def generate_attack_report_html(findings: list, target: str, output_dir=None) -> str:
    """从 findings 列表生成 HTML 报告"""
    from jinja2 import Template

    if output_dir is None:
        output_dir = REPORT_DIR
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = target.replace("://", "_").replace("/", "_").replace(":", "_")[:50]
    html_path = os.path.join(output_dir, f"attack_report_{domain}_{timestamp}.html")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    template = Template("""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>攻击报告 - {{ target }}</title>
<style>body{font-family:sans-serif;margin:40px;background:#0d1117;color:#c9d1d9}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #30363d;padding:8px;text-align:left}
th{background:#161b22} .critical{color:#ff4444} .high{color:#ff8800} .medium{color:#ffcc00}
.low{color:#4488ff} .info{color:#888}</style></head>
<body><h1>漏洞验证报告</h1>
<p><b>目标</b>: {{ target }} | <b>时间</b>: {{ timestamp }} | <b>发现</b>: {{ total }} 个漏洞</p>
<table><tr><th>#</th><th>严重程度</th><th>类型</th><th>标题</th><th>位置</th></tr>
{% for f in findings %}<tr><td>{{ loop.index }}</td>
<td class="{{ f.severity }}">{{ f.severity }}</td>
<td>{{ f.vuln_type }}</td><td>{{ f.title }}</td>
<td style="font-size:12px;word-break:break-all">{{ f.location[:80] }}</td></tr>
{% endfor %}</table>
<h2>详细发现</h2>
{% for f in findings %}<h3>#{{ loop.index }} [{{ f.severity }}] {{ f.title }}</h3>
<ul><li><b>类型</b>: {{ f.vuln_type }}</li><li><b>Payload</b>: <code>{{ f.payload[:200] }}</code></li>
<li><b>证据</b>: {{ f.evidence }}</li><li><b>描述</b>: {{ f.description }}</li>
<li><b>修复建议</b>: {{ f.remediation }}</li></ul>{% endfor %}</body></html>""")

    html = template.render(
        target=target, timestamp=datetime.now().isoformat(),
        total=len(sorted_findings), findings=sorted_findings
    )

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    log.info(f"攻击报告已生成: {html_path}")
    return html_path
