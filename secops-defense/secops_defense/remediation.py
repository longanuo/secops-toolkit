"""攻防联动模块 — 攻击发现 → 自动生成防御规则"""
import json
import os
from datetime import datetime
from secops_core.logger import get_logger
from secops_core.security_event import SecurityEvent, Severity
from secops_core.event_bus import bus

log = get_logger("remediation")


class RemediationEngine:
    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or os.path.expanduser("~/.secops/remediation")
        os.makedirs(self.output_dir, exist_ok=True)
        bus.subscribe("vuln_found", self.on_vuln_found)

    def on_vuln_found(self, event: SecurityEvent):
        log.info(f"Auto-generating rules for: {event.title}")
        rules = self.generate_rules([event])
        self._save_rules(event.category, rules)

    def generate_rules(self, events: list) -> dict:
        rules = {
            "nginx_waf": [],
            "modsecurity": [],
            "fail2ban": [],
            "nftables": [],
            "hardening": [],
        }
        for event in events:
            cat = event.category.lower()
            if cat in ("xss", "xss_stored", "xss_reflected"):
                rules["nginx_waf"].extend(self._xss_to_nginx(event))
            elif cat in ("sqli", "sqli_error", "sqli_blind"):
                rules["modsecurity"].extend(self._sqli_to_modsec(event))
                rules["nginx_waf"].extend(self._sqli_to_nginx(event))
            elif cat in ("ssti",):
                rules["nginx_waf"].extend(self._ssti_to_nginx(event))
            elif cat in ("ssrf",):
                rules["nginx_waf"].extend(self._ssrf_to_nginx(event))
            elif cat in ("rce", "command_injection"):
                rules["nginx_waf"].extend(self._rce_to_nginx(event))
            elif cat in ("lfi", "path_traversal"):
                rules["nginx_waf"].extend(self._lfi_to_nginx(event))
            elif cat in ("xxe",):
                rules["nginx_waf"].extend(self._xxe_to_nginx(event))

            if event.severity in (Severity.CRITICAL, Severity.HIGH):
                rules["fail2ban"].extend(self._to_fail2ban(event))
                rules["hardening"].append({
                    "action": "review",
                    "description": f"Review and remediate: {event.title}",
                    "location": event.location,
                })

        return rules

    def generate_waf_rules(self, findings: list) -> dict:
        events = []
        for f in findings:
            if hasattr(f, "to_dict"):
                d = f.to_dict()
                events.append(SecurityEvent(
                    source="attack_engine",
                    event_type="vuln_found",
                    severity=Severity(d.get("severity", "medium")),
                    category=d.get("vuln_type", "unknown"),
                    title=d.get("title", ""),
                    location=d.get("location", ""),
                    evidence=d.get("evidence", ""),
                ))
            elif isinstance(f, dict):
                events.append(SecurityEvent(
                    source="attack_engine",
                    event_type="vuln_found",
                    severity=Severity(f.get("severity", "medium")),
                    category=f.get("vuln_type", "unknown"),
                    title=f.get("title", ""),
                    location=f.get("location", ""),
                    evidence=f.get("evidence", ""),
                ))
        return self.generate_rules(events)

    def generate_fail2ban_filters(self, findings: list) -> dict:
        events = []
        for f in findings:
            sev = f.get("severity", "medium") if isinstance(f, dict) else getattr(f, "severity", "medium")
            if sev in ("critical", "high"):
                events.append(SecurityEvent(
                    source="attack_engine", event_type="scan_detected",
                    severity=Severity.HIGH, category="scan",
                    title="Scan activity detected",
                    location=f.get("location", "") if isinstance(f, dict) else getattr(f, "location", ""),
                ))
        return {"fail2ban": self._to_fail2ban_batch(events)}

    def generate_iptables_rules(self, findings: list) -> dict:
        ips = set()
        for f in findings:
            loc = f.get("location", "") if isinstance(f, dict) else getattr(f, "location", "")
            if loc:
                import re
                m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', loc)
                if m:
                    ips.add(m.group(1))
        rules = []
        for ip in ips:
            rules.append(f"add rule ip secops blacklist ip saddr {{ {ip} }} drop")
        return {"nftables": rules}

    def suggest_hardening(self, findings: list) -> list:
        suggestions = []
        seen = set()
        for f in findings:
            cat = f.get("vuln_type", "") if isinstance(f, dict) else getattr(f, "vuln_type", "")
            if cat and cat not in seen:
                seen.add(cat)
                suggestions.extend(self._category_to_suggestions(cat))
        return suggestions

    def _xss_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "location_block",
            "description": "Block XSS patterns",
            "rule": (
                'location ~* "((<script|javascript|onerror|onload|eval\\(|document\\.cookie))" {\n'
                '    return 403;\n}'
            ),
            "trigger": event.title,
        }]

    def _sqli_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "location_block",
            "description": "Block SQL injection patterns",
            "rule": (
                'if ($request_uri ~* "(union\\s+select|or\\s+1=1|and\\s+1=1|sleep\\(|benchmark\\()") {\n'
                '    return 403;\n}'
            ),
            "trigger": event.title,
        }]

    def _sqli_to_modsec(self, event: SecurityEvent) -> list:
        return [{
            "type": "modsecurity_rule",
            "description": "SQL injection detection rule",
            "rule": 'SecRule REQUEST_URI|REQUEST_BODY|QUERY_STRING "@rx (?i:(?:union\\s+select|or\\s+\\d+=\\d+|sleep\\(|benchmark\\())" "id:100001,phase:1,deny,status:403,log,msg:\'SQL Injection Detected\'"',
            "trigger": event.title,
        }]

    def _ssti_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "location_block",
            "description": "Block SSTI patterns",
            "rule": (
                'if ($request_uri ~* "(\\{\\{.*\\}\\}|\\{\\%.*\\%\\}|<%=|\\$\\{)") {\n'
                '    return 403;\n}'
            ),
            "trigger": event.title,
        }]

    def _ssrf_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "location_block",
            "description": "Block SSRF patterns",
            "rule": (
                'if ($request_uri ~* "(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|169\\.254|metadata\\.google)") {\n'
                '    return 403;\n}'
            ),
            "trigger": event.title,
        }]

    def _rce_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "location_block",
            "description": "Block command injection patterns",
            "rule": (
                'if ($request_uri ~* "(;\\s*(cat|ls|whoami|id|uname)|\\|\\s*(cat|ls|whoami))") {\n'
                '    return 403;\n}'
            ),
            "trigger": event.title,
        }]

    def _lfi_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "location_block",
            "description": "Block path traversal patterns",
            "rule": (
                'if ($request_uri ~* "(\\.\\.(/|\\\\)|etc/passwd|proc/self|win\\.ini)") {\n'
                '    return 403;\n}'
            ),
            "trigger": event.title,
        }]

    def _xxe_to_nginx(self, event: SecurityEvent) -> list:
        return [{
            "type": "content_type_block",
            "description": "Block XML external entity in POST body",
            "rule": (
                'location /api/ {\n'
                '    if ($content_type ~* "xml") {\n'
                '        return 403;\n'
                '    }\n'
                '}'
            ),
            "trigger": event.title,
        }]

    def _to_fail2ban(self, event: SecurityEvent) -> list:
        return [{
            "type": "fail2ban_filter",
            "name": f"secops-{event.category}",
            "pattern": f"Detected {event.category} attempt from <HOST>",
            "action": "nftables-[name]",
        }]

    def _to_fail2ban_batch(self, events: list) -> list:
        filters = []
        seen = set()
        for e in events:
            if e.category not in seen:
                seen.add(e.category)
                filters.extend(self._to_fail2ban(e))
        return filters

    def _category_to_suggestions(self, category: str) -> list:
        mapping = {
            "xss": [
                {"action": "input_validation", "description": "Implement CSP headers and input sanitization"},
                {"action": "output_encoding", "description": "Enable HTML entity encoding on all output"},
            ],
            "sqli": [
                {"action": "parameterized_queries", "description": "Use prepared statements for all DB queries"},
                {"action": "waf_rules", "description": "Deploy ModSecurity SQL injection rules"},
            ],
            "ssti": [
                {"action": "sandbox", "description": "Use sandboxed template engine (Jinja2 with sandboxed environment)"},
                {"action": "input_validation", "description": "Block template syntax in user input"},
            ],
            "ssrf": [
                {"action": "url_whitelist", "description": "Implement URL whitelist for server-side requests"},
                {"action": "network_segmentation", "description": "Isolate internal services from user-facing servers"},
            ],
            "rce": [
                {"action": "input_sanitization", "description": "Sanitize all shell command inputs"},
                {"action": "least_privilege", "description": "Run web server with minimal permissions"},
            ],
            "lfi": [
                {"action": "path_validation", "description": "Validate and sanitize file paths"},
                {"action": "chroot", "description": "Use chroot jail for file operations"},
            ],
            "xxe": [
                {"action": "xml_disable_external", "description": "Disable external entity parsing in XML parser"},
                {"action": "use_json", "description": "Replace XML with JSON for data exchange"},
            ],
            "jwt": [
                {"action": "algorithm_validation", "description": "Validate JWT algorithm server-side"},
                {"action": "key_rotation", "description": "Implement regular JWT key rotation"},
            ],
            "idor": [
                {"action": "access_control", "description": "Implement proper authorization checks"},
                {"action": "reference_validation", "description": "Validate object ownership before access"},
            ],
            "cors": [
                {"action": "origin_validation", "description": "Validate Origin header against whitelist"},
                {"action": "credentials", "description": "Avoid wildcard with credentials"},
            ],
            "redirect": [
                {"action": "url_whitelist", "description": "Whitelist allowed redirect destinations"},
            ],
        }
        return mapping.get(category, [
            {"action": "manual_review", "description": f"Manual review required for: {category}"}
        ])

    def _save_rules(self, category: str, rules: dict):
        filename = os.path.join(self.output_dir, f"remediation_{category}_{datetime.now():%Y%m%d_%H%M%S}.json")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
        log.info(f"Rules saved to: {filename}")


def on_vuln_found(event: SecurityEvent):
    engine = RemediationEngine()
    engine.on_vuln_found(event)


def generate_waf_rules(findings: list) -> dict:
    engine = RemediationEngine()
    return engine.generate_waf_rules(findings)


def suggest_hardening(findings: list) -> list:
    engine = RemediationEngine()
    return engine.suggest_hardening(findings)
