"""Agent 注册表 — 管理所有可用的攻击/防御 Agent"""
from dataclasses import dataclass, field
from typing import Callable, Optional
from secops_core.task import TaskType


@dataclass
class AgentRef:
    name: str
    type: TaskType
    capabilities: list
    module_path: str
    entry_function: str
    priority: int = 5
    max_concurrent: int = 1
    _instance: Optional[object] = field(default=None, repr=False)

    def load(self):
        if self._instance is not None:
            return self._instance
        import importlib
        mod = importlib.import_module(self.module_path)
        func = getattr(mod, self.entry_function)
        self._instance = func
        return func


class AgentRegistry:
    def __init__(self):
        self._agents: list[AgentRef] = []

    def register(self, agent: AgentRef):
        self._agents.append(agent)

    def match(self, task_type: TaskType, capabilities: list = None) -> list[AgentRef]:
        candidates = [a for a in self._agents if a.type == task_type]
        if capabilities:
            candidates = [
                a for a in candidates
                if any(c in a.capabilities for c in capabilities)
            ]
        return sorted(candidates, key=lambda a: -a.priority)

    def get(self, name: str) -> Optional[AgentRef]:
        for a in self._agents:
            if a.name == name:
                return a
        return None

    def all_agents(self) -> list[AgentRef]:
        return list(self._agents)

    @classmethod
    def default(cls) -> "AgentRegistry":
        reg = cls()
        reg._auto_register()
        return reg

    def _auto_register(self):
        self.register(AgentRef(
            name="attack_engine",
            type=TaskType.ATTACK,
            capabilities=["xss", "sqli", "ssti", "lfi", "ssrf", "xxe", "rce",
                          "nosqli", "infoleak", "jwt", "idor", "cors", "redirect"],
            module_path="secops_offense.attack_engine",
            entry_function="start_attack",
            priority=10,
        ))
        self.register(AgentRef(
            name="evaluator",
            type=TaskType.DEFENSE,
            capabilities=["check", "evaluator", "体检"],
            module_path="secops_defense.evaluator",
            entry_function="run_evaluation",
            priority=10,
        ))
        self.register(AgentRef(
            name="hardener",
            type=TaskType.DEFENSE,
            capabilities=["harden", "加固"],
            module_path="secops_defense.hardener",
            entry_function="run_hardening",
            priority=5,
        ))
        self.register(AgentRef(
            name="firewall",
            type=TaskType.DEFENSE,
            capabilities=["firewall", "防火墙"],
            module_path="secops_defense.firewall",
            entry_function="update_threat_intel_firewall",
            priority=5,
        ))
        self.register(AgentRef(
            name="waf",
            type=TaskType.DEFENSE,
            capabilities=["waf"],
            module_path="secops_defense.waf",
            entry_function="detect_waf",
            priority=5,
        ))
        self.register(AgentRef(
            name="anomaly",
            type=TaskType.DEFENSE,
            capabilities=["anomaly", "异常"],
            module_path="secops_defense.anomaly",
            entry_function="run_anomaly_detection",
            priority=5,
        ))
        self.register(AgentRef(
            name="threat_intel",
            type=TaskType.DEFENSE,
            capabilities=["intel", "情报"],
            module_path="secops_defense.threat_intel",
            entry_function="get_threat_summary",
            priority=5,
        ))
        self.register(AgentRef(
            name="github_offense",
            type=TaskType.LEARN,
            capabilities=["learn", "github", "学习"],
            module_path="secops_offense.github_offense",
            entry_function="learn_from_github",
            priority=5,
        ))
