"""动态代理池 — 全局代理轮换与健康检查"""
import random
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from collections import deque
from secops_core.logger import get_logger
from secops_core.config import CACHE_DIR

log = get_logger("proxy_pool")

PROXY_FILE = CACHE_DIR / "proxies.txt"
HEALTH_CHECK_INTERVAL = 300  # 5分钟
MAX_FAIL_COUNT = 3
PROXY_TIMEOUT = 10


@dataclass
class Proxy:
    url: str
    protocol: str = "http"
    fail_count: int = 0
    success_count: int = 0
    last_used: float = 0
    last_check: float = 0
    is_healthy: bool = True
    avg_latency: float = 0
    _latencies: list = field(default_factory=list, repr=False)

    @property
    def weight(self) -> float:
        if not self.is_healthy or self.fail_count >= MAX_FAIL_COUNT:
            return 0
        success_rate = self.success_count / max(1, self.success_count + self.fail_count)
        latency_penalty = min(1.0, self.avg_latency / 5.0)
        return success_rate * (1 - latency_penalty * 0.5)

    def record_success(self, latency: float):
        self.success_count += 1
        self.fail_count = max(0, self.fail_count - 1)
        self._latencies.append(latency)
        if len(self._latencies) > 20:
            self._latencies = self._latencies[-20:]
        self.avg_latency = sum(self._latencies) / len(self._latencies)
        self.last_used = time.time()
        self.is_healthy = True

    def record_failure(self):
        self.fail_count += 1
        self.last_used = time.time()
        if self.fail_count >= MAX_FAIL_COUNT:
            self.is_healthy = False
            log.warning(f"Proxy marked unhealthy: {self.url} (failures: {self.fail_count})")

    def to_dict(self) -> dict:
        return {
            "http": self.url,
            "https": self.url,
        }


class ProxyPool:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._proxies: deque[Proxy] = deque()
        self._lock = threading.RLock()
        self._last_load = 0
        self._rotation_index = 0
        self._load_proxies()

    def _load_proxies(self):
        if PROXY_FILE.exists():
            try:
                lines = PROXY_FILE.read_text().strip().splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        proxy = Proxy(url=line)
                        self._proxies.append(proxy)
                log.info(f"Loaded {len(self._proxies)} proxies from file")
            except Exception as e:
                log.error(f"Failed to load proxies: {e}")
        self._last_load = time.time()

    def add_proxy(self, url: str, protocol: str = "http"):
        with self._lock:
            proxy = Proxy(url=url, protocol=protocol)
            self._proxies.append(proxy)
            log.info(f"Added proxy: {url}")

    def remove_proxy(self, url: str):
        with self._lock:
            self._proxies = deque(p for p in self._proxies if p.url != url)

    def get_proxy(self, strategy: str = "weighted_random") -> Optional[dict]:
        with self._lock:
            healthy = [p for p in self._proxies if p.is_healthy and p.weight > 0]
            if not healthy:
                if self._proxies:
                    for p in self._proxies:
                        p.fail_count = 0
                        p.is_healthy = True
                    healthy = list(self._proxies)
                else:
                    return None

            if strategy == "round_robin":
                proxy = healthy[self._rotation_index % len(healthy)]
                self._rotation_index += 1
            elif strategy == "weighted_random":
                weights = [p.weight for p in healthy]
                total = sum(weights)
                if total <= 0:
                    proxy = random.choice(healthy)
                else:
                    r = random.uniform(0, total)
                    cumulative = 0
                    proxy = healthy[0]
                    for p, w in zip(healthy, weights):
                        cumulative += w
                        if r <= cumulative:
                            proxy = p
                            break
            elif strategy == "least_latency":
                proxy = min(healthy, key=lambda p: p.avg_latency or float('inf'))
            else:
                proxy = random.choice(healthy)

            proxy.last_used = time.time()
            return proxy.to_dict()

    def report_success(self, proxy_dict: dict, latency: float):
        url = proxy_dict.get("http", "")
        with self._lock:
            for p in self._proxies:
                if p.url == url:
                    p.record_success(latency)
                    break

    def report_failure(self, proxy_dict: dict):
        url = proxy_dict.get("http", "")
        with self._lock:
            for p in self._proxies:
                if p.url == url:
                    p.record_failure()
                    break

    @property
    def stats(self) -> dict:
        with self._lock:
            healthy = sum(1 for p in self._proxies if p.is_healthy)
            return {
                "total": len(self._proxies),
                "healthy": healthy,
                "unhealthy": len(self._proxies) - healthy,
            }

    def get_no_proxy(self) -> dict:
        return {"http": None, "https": None}


pool = ProxyPool()
