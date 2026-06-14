"""统一安全事件模型 — 攻防共用"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json
import uuid


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityEvent:
    source: str
    event_type: str
    severity: Severity
    category: str
    title: str
    description: str = ""
    location: str = ""
    evidence: str = ""
    remediation: str = ""
    metadata: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence[:500],
            "remediation": self.remediation,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_finding(cls, finding) -> "SecurityEvent":
        sev_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return cls(
            source="attack_engine",
            event_type="vuln_found",
            severity=sev_map.get(getattr(finding, "severity", "medium"), Severity.MEDIUM),
            category=getattr(finding, "vuln_type", "unknown"),
            title=getattr(finding, "title", "Unknown vulnerability"),
            description=getattr(finding, "description", ""),
            location=getattr(finding, "location", ""),
            evidence=getattr(finding, "evidence", ""),
            remediation=getattr(finding, "remediation", ""),
        )

    @classmethod
    def from_scan_data(cls, source: str, scan_data: dict) -> list:
        events = []
        for item in scan_data.get("findings", []):
            sev = item.get("severity", "medium")
            sev_enum = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }.get(sev, Severity.MEDIUM)
            events.append(cls(
                source=source,
                event_type=item.get("event_type", "config_weak"),
                severity=sev_enum,
                category=item.get("category", "unknown"),
                title=item.get("title", ""),
                description=item.get("description", ""),
                location=item.get("location", ""),
                evidence=item.get("evidence", ""),
                remediation=item.get("remediation", ""),
            ))
        return events
