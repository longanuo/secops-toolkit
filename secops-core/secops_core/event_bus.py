"""进程内事件总线 — 解耦攻防模块"""
from typing import Callable, Any
from secops_core.logger import get_logger

log = get_logger("event_bus")


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(self, event_type: str, handler: Callable):
        self._subscribers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: Callable):
        handlers = self._subscribers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    def publish(self, event_type: str, data: Any = None):
        for handler in self._subscribers.get(event_type, []):
            try:
                handler(data)
            except Exception as e:
                log.error(f"Event handler error [{event_type}]: {e}")

    def clear(self):
        self._subscribers.clear()

    @property
    def subscriber_count(self) -> dict[str, int]:
        return {k: len(v) for k, v in self._subscribers.items()}


bus = EventBus()
