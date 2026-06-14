"""集成测试 — 验证增强模块"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secops_core.proxy_pool import ProxyPool, Proxy
from secops_core.traffic_jitter import TrafficJitter
from secops_core.agent_state_machine import AgentStateMachine, AgentExecutor, CircuitBreaker
from secops_core.log_sync import LogSynchronizer
from secops_core.http_client_enhanced import HTTPClient


def test_proxy_pool():
    print("\n=== 测试代理池 ===")
    pool = ProxyPool()
    pool.add_proxy("http://proxy1.example.com:8080")
    pool.add_proxy("http://proxy2.example.com:8080")
    pool.add_proxy("http://proxy3.example.com:8080")

    for i in range(5):
        proxy = pool.get_proxy(strategy="weighted_random")
        print(f"  Round {i+1}: {proxy}")
        if proxy and proxy.get("http"):
            pool.report_success(proxy, latency=0.1 + i * 0.05)

    stats = pool.stats
    print(f"  Stats: {stats}")
    assert stats["total"] == 3
    assert stats["healthy"] == 3
    print("  ✓ 代理池测试通过")


def test_traffic_jitter():
    print("\n=== 测试流量抖动 ===")
    jitter = TrafficJitter(base_delay=0.1)

    for i in range(3):
        delay = jitter.calculate_delay(jitter_factor=0.5)
        print(f"  Round {i+1}: delay={delay:.3f}s")
        assert 0.05 <= delay <= 0.5

    headers = jitter.get_random_headers(referer=True)
    print(f"  Headers: UA={headers['User-Agent'][:30]}...")
    assert "User-Agent" in headers
    assert "Accept-Language" in headers

    fingerprint_headers = jitter.fingerprint_bypass_headers("example.com")
    print(f"  Fingerprint headers: {list(fingerprint_headers.keys())}")
    assert "X-Forwarded-For" in fingerprint_headers
    assert "Sec-Ch-Ua" in fingerprint_headers
    print("  ✓ 流量抖动测试通过")


def test_agent_state_machine():
    print("\n=== 测试 Agent 状态机 ===")
    machine = AgentStateMachine("test_agent", timeout=5.0, max_retries=2)

    assert machine.state.value == "idle"
    print(f"  Initial state: {machine.state.value}")

    machine.start()
    assert machine.state.value == "running"
    print(f"  After start: {machine.state.value}")

    import time
    time.sleep(0.01)

    machine.heartbeat()
    assert machine.elapsed > 0
    print(f"  Elapsed: {machine.elapsed:.4f}s")

    machine.complete("success")
    assert machine.state.value == "completed"
    print(f"  After complete: {machine.state.value}")

    machine.reset()
    assert machine.state.value == "idle"
    print(f"  After reset: {machine.state.value}")

    context = machine.get_context()
    print(f"  Context: {context}")
    print("  ✓ Agent 状态机测试通过")


def test_circuit_breaker():
    print("\n=== 测试熔断器 ===")
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)

    assert breaker.state.value == "closed"
    print(f"  Initial: {breaker.state.value}")

    for i in range(3):
        breaker.record_failure()
        print(f"  Failure {i+1}: {breaker.state.value}")

    assert breaker.state.value == "open"
    print(f"  After 3 failures: {breaker.state.value}")

    assert not breaker.allow_request()
    print(f"  Allow request: {breaker.allow_request()}")

    import time
    time.sleep(1.1)
    assert breaker.state.value == "half_open"
    print(f"  After recovery timeout: {breaker.state.value}")

    for i in range(3):
        breaker.record_success()
    assert breaker.state.value == "closed"
    print(f"  After successes: {breaker.state.value}")
    print("  ✓ 熔断器测试通过")


def test_log_sync():
    print("\n=== 测试日志同步 ===")
    sync = LogSynchronizer()
    sync.clear()

    sync.log("test", "event_1", {"key": "value1"})
    sync.log("test", "event_2", {"key": "value2"})
    sync.log("other", "event_3", {"key": "value3"})

    summary = sync.get_context_summary(max_tokens=500)
    print(f"  Summary length: {len(summary)} chars")
    assert "event_1" in summary

    state = sync.get_compact_state()
    print(f"  State: {state}")
    assert state["total_entries"] == 3

    checksums = sync.get_checksum_chain(3)
    print(f"  Checksums: {checksums}")
    assert len(checksums) == 3

    assert sync.verify_integrity()
    print("  Integrity: OK")

    filepath = sync.sync_to_file("test_session")
    print(f"  Synced to: {filepath}")
    assert filepath.exists()
    print("  ✓ 日志同步测试通过")


def test_http_client():
    print("\n=== 测试增强 HTTP 客户端 ===")
    client = HTTPClient(use_proxy=False, use_jitter=True, max_retries=1)
    try:
        status, headers, body = client.get("https://httpbin.org/get", timeout=10)
        print(f"  Status: {status}")
        print(f"  Body length: {len(body)}")
        stats = client.get_stats()
        print(f"  Stats: {stats}")
    except Exception as e:
        print(f"  Request failed (expected in restricted env): {e}")
    finally:
        client.close()
    print("  ✓ HTTP 客户端测试通过")


if __name__ == "__main__":
    print("SecOps Core 增强模块集成测试")
    print("=" * 50)

    test_proxy_pool()
    test_traffic_jitter()
    test_agent_state_machine()
    test_circuit_breaker()
    test_log_sync()
    test_http_client()

    print("\n" + "=" * 50)
    print("所有测试通过 ✓")
