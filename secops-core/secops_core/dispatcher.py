"""TaskRouter + TaskQueue — 增强版调度入口（带熔断与日志同步）"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from secops_core.task import Task, TaskType, TaskStatus, TaskPriority
from secops_core.result import TaskResult
from secops_core.agent_registry import AgentRegistry
from secops_core.event_bus import bus
from secops_core.logger import get_logger, correlation_id
from secops_core.proxy_pool import pool as proxy_pool
from secops_core.traffic_jitter import jitter
from secops_core.agent_state_machine import AgentExecutor, CircuitBreaker
from secops_core.log_sync import sync as log_sync
from secops_core.config import (
    AGENT_TIMEOUT, AGENT_MAX_RETRIES,
    CIRCUIT_BREAKER_THRESHOLD, CIRCUIT_RECOVERY_TIMEOUT,
    PROXY_POOL_ENABLED, TRAFFIC_JITTER_ENABLED,
)

log = get_logger("dispatcher")

ATTACK_KEYWORDS = ["扫描", "漏洞", "攻击", "渗透", "attack", "scan", "exploit",
                    "xss", "sqli", "ssti", "ssrf", "xxe", "rce"]
DEFENSE_KEYWORDS = ["体检", "加固", "防火墙", "巡检", "check", "harden", "firewall",
                     "防御", "waf", "anomaly", "intel"]
LEARN_KEYWORDS = ["学习", "github", "learn", "爬取", "情报"]
HYBRID_KEYWORDS = ["扫描+加固", "扫描加固", "全量扫描", "attack+harden"]


class TaskRouter:
    def __init__(self, registry: AgentRegistry = None, max_workers: int = 4):
        self.registry = registry or AgentRegistry.default()
        self.max_workers = max_workers
        self._circuit_config = {
            "failure_threshold": CIRCUIT_BREAKER_THRESHOLD,
            "recovery_timeout": CIRCUIT_RECOVERY_TIMEOUT,
        }
        self._agent_states = {}
        self._start_time = time.time()

    def route(self, input_text: str, **overrides) -> TaskResult:
        task = self.parse_and_build(input_text, **overrides)
        return self.execute(task)

    def parse_and_build(self, input_text: str, **overrides) -> Task:
        task_type, params = self._parse_intent(input_text)
        target = params.pop("target", overrides.get("target", ""))
        modules = params.pop("modules", overrides.get("modules", []))

        task = Task(
            type=task_type,
            target=target,
            modules=modules,
            params=params,
            priority=overrides.get("priority", TaskPriority.NORMAL),
            timeout=overrides.get("timeout", AGENT_TIMEOUT),
        )
        return task

    def execute(self, task: Task) -> TaskResult:
        task.start()
        corr = correlation_id.set(task.id)
        session_id = f"task_{task.id}"
        log_sync.start_session(session_id)

        log_sync.log("dispatcher", "task_started", {
            "task_id": task.id,
            "type": task.type.value,
            "target": task.target,
            "modules": task.modules,
        })

        try:
            if PROXY_POOL_ENABLED:
                proxy_stats = proxy_pool.stats
                log_sync.log("dispatcher", "proxy_stats", proxy_stats)

            agents = self.registry.match(task.type, task.modules or None)
            if not agents:
                task.fail("No matching agent found")
                return TaskResult(
                    task_id=task.id, agent="none", success=False,
                    error="No matching agent found",
                )

            start = time.time()
            results = []

            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {}
                for agent in agents[:self.max_workers]:
                    agent_key = f"{agent.name}_{task.id}"
                    executor = AgentExecutor(
                        agent_id=agent_key,
                        func=lambda a=agent, t=task: self._run_agent(a, t),
                        timeout=task.timeout,
                        max_retries=AGENT_MAX_RETRIES,
                        circuit_config=self._circuit_config,
                    )
                    self._agent_states[agent_key] = executor.machine

                    f = pool.submit(executor.execute)
                    futures[f] = agent

                for f in as_completed(futures, timeout=task.timeout + 30):
                    agent = futures[f]
                    try:
                        result = f.result(timeout=5)
                        results.append(result)
                        log_sync.log("dispatcher", "agent_completed", {
                            "agent": agent.name,
                            "success": result.success,
                            "duration_ms": result.duration_ms,
                        })
                    except TimeoutError:
                        log.error(f"Agent {agent.name} result retrieval timed out")
                        results.append(TaskResult(
                            task_id=task.id, agent=agent.name,
                            success=False, error="Result retrieval timed out",
                        ))
                    except Exception as e:
                        log.error(f"Agent {agent.name} failed: {e}")
                        results.append(TaskResult(
                            task_id=task.id, agent=agent.name,
                            success=False, error=str(e),
                        ))

            duration = int((time.time() - start) * 1000)
            merged = self._merge_results(task.id, results, duration)
            task.succeed(merged.to_dict())

            log_sync.log("dispatcher", "task_completed", {
                "task_id": task.id,
                "total_duration_ms": duration,
                "results_count": len(results),
                "success_count": sum(1 for r in results if r.success),
            })

            bus.publish("task_complete", merged)
            return merged

        except Exception as e:
            task.fail(str(e))
            log_sync.log("dispatcher", "task_failed", {
                "task_id": task.id,
                "error": str(e),
            })
            return TaskResult(
                task_id=task.id, agent="router", success=False, error=str(e),
            )
        finally:
            correlation_id.reset(corr)

    def _run_agent(self, agent, task: Task) -> TaskResult:
        func = agent.load()
        start = time.time()
        try:
            jitter.wait() if TRAFFIC_JITTER_ENABLED else None

            if agent.type == TaskType.ATTACK:
                data = func(task.target, modules=task.modules, **task.params)
            elif agent.type == TaskType.DEFENSE:
                data = func(**task.params)
            elif agent.type == TaskType.LEARN:
                data = func(**task.params)
            else:
                data = func(**task.params)

            duration = int((time.time() - start) * 1000)
            return TaskResult(
                task_id=task.id, agent=agent.name,
                success=True, data=data if isinstance(data, dict) else {"result": data},
                duration_ms=duration,
            )
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            return TaskResult(
                task_id=task.id, agent=agent.name,
                success=False, error=str(e), duration_ms=duration,
            )

    def _merge_results(self, task_id: str, results: list, total_ms: int) -> TaskResult:
        merged_data = {}
        all_findings = []
        all_events = []
        errors = []
        for r in results:
            if r.success:
                merged_data.update(r.data)
                all_findings.extend(r.findings)
                all_events.extend(r.events)
            else:
                errors.append(f"{r.agent}: {r.error}")
        return TaskResult(
            task_id=task_id,
            agent="router",
            success=len(errors) == 0,
            data=merged_data,
            findings=all_findings,
            events=all_events,
            duration_ms=total_ms,
            error="; ".join(errors) if errors else None,
        )

    def _parse_intent(self, text: str):
        text_lower = text.lower()
        if any(k in text_lower for k in HYBRID_KEYWORDS):
            return TaskType.HYBRID, self._extract_params(text)
        if any(k in text_lower for k in LEARN_KEYWORDS):
            return TaskType.LEARN, self._extract_params(text)
        if any(k in text_lower for k in ATTACK_KEYWORDS):
            return TaskType.ATTACK, self._extract_params(text)
        if any(k in text_lower for k in DEFENSE_KEYWORDS):
            return TaskType.DEFENSE, self._extract_params(text)
        return TaskType.DEFENSE, self._extract_params(text)

    def _extract_params(self, text: str) -> dict:
        params = {}
        for part in text.split():
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v
        return params

    def get_system_status(self) -> dict:
        return {
            "uptime_seconds": int(time.time() - self._start_time),
            "agent_states": {
                k: v.get_context() for k, v in self._agent_states.items()
            },
            "proxy_pool": proxy_pool.stats if PROXY_POOL_ENABLED else None,
            "jitter_stats": jitter.get_stats() if TRAFFIC_JITTER_ENABLED else None,
            "log_sync_integrity": log_sync.verify_integrity(),
        }

    @classmethod
    def default(cls) -> "TaskRouter":
        return cls(registry=AgentRegistry.default())
