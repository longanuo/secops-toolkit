"""TaskResult 结构化输出"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json


@dataclass
class TaskResult:
    task_id: str
    agent: str
    success: bool
    data: dict = field(default_factory=list)
    findings: list = field(default_factory=list)
    events: list = field(default_factory=list)
    duration_ms: int = 0
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "agent": self.agent,
            "success": self.success,
            "data": self.data,
            "findings": self.findings,
            "events": self.events,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "TaskResult":
        result = cls(
            task_id=data["task_id"],
            agent=data["agent"],
            success=data.get("success", True),
            data=data.get("data", {}),
            findings=data.get("findings", []),
            events=data.get("events", []),
            duration_ms=data.get("duration_ms", 0),
            error=data.get("error"),
        )
        if data.get("timestamp"):
            result.timestamp = datetime.fromisoformat(data["timestamp"])
        return result
