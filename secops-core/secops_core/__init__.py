"""SecOps Core - 共享内核模块"""
__version__ = "4.0.0"

from .task import Task, TaskType, TaskStatus, TaskPriority
from .result import TaskResult
from .security_event import SecurityEvent, Severity
from .event_bus import EventBus, bus
from .proxy_pool import ProxyPool, pool as proxy_pool
from .traffic_jitter import TrafficJitter, jitter
from .agent_state_machine import (
    AgentStateMachine, AgentExecutor, AgentState,
    CircuitBreaker, CircuitState,
)
from .log_sync import LogSynchronizer, sync as log_sync
from .http_client_enhanced import HTTPClient
