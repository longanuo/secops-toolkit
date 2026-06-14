"""Agent 状态机 — 带超时熔断与容错机制"""
import time
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, Any, Dict
from secops_core.logger import get_logger

log = get_logger("agent_state_machine")


class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    TIMEOUT = "timeout"
    FAILED = "failed"
    COMPLETED = "completed"
    CIRCUIT_OPEN = "circuit_open"


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max: int = 3
    _state: CircuitState = field(default=CircuitState.CLOSED, repr=False)
    _failure_count: int = field(default=0, repr=False)
    _last_failure_time: float = field(default=0, repr=False)
    _half_open_successes: int = field(default=0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._last_failure_time > self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_successes = 0
                    log.info("Circuit breaker: OPEN -> HALF_OPEN")
            return self._state

    def record_success(self):
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_successes += 1
                if self._half_open_successes >= self.half_open_max:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    log.info("Circuit breaker: HALF_OPEN -> CLOSED")
            elif self._state == CircuitState.CLOSED:
                self._failure_count = max(0, self._failure_count - 1)

    def record_failure(self):
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                log.warning("Circuit breaker: HALF_OPEN -> OPEN")
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                log.warning(f"Circuit breaker: CLOSED -> OPEN (failures: {self._failure_count})")

    def allow_request(self) -> bool:
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        elif state == CircuitState.HALF_OPEN:
            return self._half_open_successes < self.half_open_max
        return False

    def reset(self):
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_successes = 0


@dataclass
class AgentContext:
    agent_id: str
    state: AgentState = AgentState.IDLE
    start_time: float = 0
    timeout: float = 300.0
    last_heartbeat: float = 0
    result: Any = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    metadata: Dict = field(default_factory=dict)


class AgentStateMachine:
    def __init__(self, agent_id: str, timeout: float = 300.0,
                 max_retries: int = 3, circuit_config: dict = None):
        self.agent_id = agent_id
        self._lock = threading.RLock()
        self._context = AgentContext(
            agent_id=agent_id,
            timeout=timeout,
            max_retries=max_retries,
        )
        self._circuit = CircuitBreaker(**(circuit_config or {}))
        self._transitions = {
            (AgentState.IDLE, AgentState.RUNNING),
            (AgentState.RUNNING, AgentState.COMPLETED),
            (AgentState.RUNNING, AgentState.FAILED),
            (AgentState.RUNNING, AgentState.TIMEOUT),
            (AgentState.RUNNING, AgentState.PAUSED),
            (AgentState.PAUSED, AgentState.RUNNING),
            (AgentState.TIMEOUT, AgentState.RUNNING),
            (AgentState.TIMEOUT, AgentState.IDLE),
            (AgentState.FAILED, AgentState.RUNNING),
            (AgentState.FAILED, AgentState.IDLE),
            (AgentState.COMPLETED, AgentState.IDLE),
        }
        self._state_history = []

    def _transition(self, new_state: AgentState, reason: str = "") -> bool:
        with self._lock:
            old_state = self._context.state
            if (old_state, new_state) not in self._transitions:
                log.warning(f"Invalid transition: {old_state.value} -> {new_state.value}")
                return False

            self._context.state = new_state
            self._state_history.append({
                "from": old_state.value,
                "to": new_state.value,
                "reason": reason,
                "timestamp": time.time(),
            })
            log.debug(f"Agent {self.agent_id}: {old_state.value} -> {new_state.value} ({reason})")
            return True

    def start(self) -> bool:
        if not self._circuit.allow_request():
            log.warning(f"Agent {self.agent_id}: Circuit breaker open, rejecting start")
            return False
        self._context.start_time = time.time()
        self._context.last_heartbeat = time.time()
        return self._transition(AgentState.RUNNING, "started")

    def heartbeat(self):
        with self._lock:
            self._context.last_heartbeat = time.time()

    def complete(self, result: Any) -> bool:
        self._circuit.record_success()
        self._context.result = result
        return self._transition(AgentState.COMPLETED, "completed")

    def fail(self, error: str) -> bool:
        self._circuit.record_failure()
        self._context.error = error
        return self._transition(AgentState.FAILED, error)

    def timeout_hit(self) -> bool:
        self._circuit.record_failure()
        return self._transition(AgentState.TIMEOUT, "timeout exceeded")

    def retry(self) -> bool:
        if self._context.retry_count >= self._context.max_retries:
            log.warning(f"Agent {self.agent_id}: Max retries exceeded")
            return False
        self._context.retry_count += 1
        self._context.error = None
        return self._transition(AgentState.RUNNING, f"retry #{self._context.retry_count}")

    def pause(self) -> bool:
        return self._transition(AgentState.PAUSED, "paused")

    def resume(self) -> bool:
        return self._transition(AgentState.RUNNING, "resumed")

    def reset(self) -> bool:
        with self._lock:
            self._context = AgentContext(
                agent_id=self.agent_id,
                timeout=self._context.timeout,
                max_retries=self._context.max_retries,
            )
            self._circuit.reset()
            return True

    @property
    def state(self) -> AgentState:
        return self._context.state

    @property
    def is_running(self) -> bool:
        return self._context.state == AgentState.RUNNING

    @property
    def is_failed(self) -> bool:
        return self._context.state in (AgentState.FAILED, AgentState.TIMEOUT)

    @property
    def elapsed(self) -> float:
        if self._context.start_time == 0:
            return 0
        return time.time() - self._context.start_time

    @property
    def is_timed_out(self) -> bool:
        if not self.is_running:
            return False
        return self.elapsed > self._context.timeout

    def get_context(self) -> dict:
        return {
            "agent_id": self._context.agent_id,
            "state": self._context.state.value,
            "elapsed": round(self.elapsed, 2),
            "timeout": self._context.timeout,
            "retry_count": self._context.retry_count,
            "error": self._context.error,
            "circuit_state": self._circuit.state.value,
        }


class AgentExecutor:
    def __init__(self, agent_id: str, func: Callable, timeout: float = 300.0,
                 max_retries: int = 3, circuit_config: dict = None):
        self.machine = AgentStateMachine(agent_id, timeout, max_retries, circuit_config)
        self._func = func
        self._monitor_thread = None
        self._stop_monitor = threading.Event()

    def execute(self, *args, **kwargs) -> Any:
        if not self.machine.start():
            raise RuntimeError(f"Agent {self.machine.agent_id} rejected by circuit breaker")

        self._start_monitor()

        try:
            result = self._func(*args, **kwargs)
            self.machine.complete(result)
            return result
        except Exception as e:
            self.machine.fail(str(e))
            if self.machine.retry():
                return self.execute(*args, **kwargs)
            raise
        finally:
            self._stop_monitor.set()

    def _start_monitor(self):
        self._stop_monitor.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

    def _monitor_loop(self):
        while not self._stop_monitor.wait(timeout=1.0):
            if self.machine.is_timed_out:
                log.error(f"Agent {self.machine.agent_id}: Timeout after {self.machine.elapsed}s")
                self.machine.timeout_hit()
                return
            self.machine.heartbeat()
