"""Task 数据结构 — 调度器核心模型"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class TaskType(Enum):
    ATTACK = "attack"
    DEFENSE = "defense"
    HYBRID = "hybrid"
    LEARN = "learn"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


class TaskPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class Task:
    type: TaskType
    target: str = ""
    modules: list = field(default_factory=list)
    params: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    depends_on: list = field(default_factory=list)
    timeout: int = 300
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[dict] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    def start(self):
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now()

    def succeed(self, result: dict):
        self.status = TaskStatus.SUCCESS
        self.result = result
        self.finished_at = datetime.now()

    def fail(self, error: str):
        self.status = TaskStatus.FAILED
        self.error = error
        self.finished_at = datetime.now()

    def block(self, reason: str):
        self.status = TaskStatus.BLOCKED
        self.error = reason

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "status": self.status.value,
            "priority": self.priority.value,
            "target": self.target,
            "modules": self.modules,
            "params": self.params,
            "depends_on": self.depends_on,
            "timeout": self.timeout,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        task = cls(
            id=data.get("id", uuid.uuid4().hex[:8]),
            type=TaskType(data["type"]),
            target=data.get("target", ""),
            modules=data.get("modules", []),
            params=data.get("params", {}),
            priority=TaskPriority(data.get("priority", 1)),
            depends_on=data.get("depends_on", []),
            timeout=data.get("timeout", 300),
        )
        task.status = TaskStatus(data.get("status", "pending"))
        task.result = data.get("result")
        task.error = data.get("error")
        if data.get("created_at"):
            task.created_at = datetime.fromisoformat(data["created_at"])
        if data.get("started_at"):
            task.started_at = datetime.fromisoformat(data["started_at"])
        if data.get("finished_at"):
            task.finished_at = datetime.fromisoformat(data["finished_at"])
        return task
