"""漏洞发现数据结构"""
from datetime import datetime


class Finding:
    def __init__(self, vuln_type, severity, title, location,
                 payload="", evidence="", description="", remediation=""):
        self.vuln_type = vuln_type
        self.severity = severity
        self.title = title
        self.location = location
        self.payload = payload
        self.evidence = evidence
        self.description = description
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "vuln_type": self.vuln_type, "severity": self.severity,
            "title": self.title, "location": self.location,
            "payload": self.payload[:200], "evidence": self.evidence[:500],
            "description": self.description, "remediation": self.remediation,
            "timestamp": self.timestamp,
        }

    def __str__(self):
        sev_icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": ".", "info": "i"}
        return (f"  [{sev_icon.get(self.severity, '?')}] [{self.severity.upper()}] {self.title}\n"
                f"      位置: {self.location}\n"
                f"      Payload: {self.payload[:80]}\n"
                f"      证据: {self.evidence[:120]}")
