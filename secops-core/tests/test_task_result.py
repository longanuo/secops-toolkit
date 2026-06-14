import unittest
import json
from datetime import datetime
from secops_core.task import Task, TaskType, TaskStatus, TaskPriority
from secops_core.result import TaskResult


class TestTaskType(unittest.TestCase):
    def test_values(self):
        self.assertEqual(TaskType.ATTACK.value, "attack")
        self.assertEqual(TaskType.DEFENSE.value, "defense")
        self.assertEqual(TaskType.HYBRID.value, "hybrid")
        self.assertEqual(TaskType.LEARN.value, "learn")


class TestTaskStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(TaskStatus.PENDING.value, "pending")
        self.assertEqual(TaskStatus.RUNNING.value, "running")
        self.assertEqual(TaskStatus.SUCCESS.value, "success")
        self.assertEqual(TaskStatus.FAILED.value, "failed")
        self.assertEqual(TaskStatus.BLOCKED.value, "blocked")


class TestTaskPriority(unittest.TestCase):
    def test_values(self):
        self.assertEqual(TaskPriority.LOW.value, 0)
        self.assertEqual(TaskPriority.NORMAL.value, 1)
        self.assertEqual(TaskPriority.HIGH.value, 2)
        self.assertEqual(TaskPriority.CRITICAL.value, 3)


class TestTask(unittest.TestCase):
    def test_init_defaults(self):
        task = Task(type=TaskType.ATTACK)
        self.assertEqual(task.status, TaskStatus.PENDING)
        self.assertEqual(task.priority, TaskPriority.NORMAL)
        self.assertEqual(task.timeout, 300)
        self.assertIsNotNone(task.id)
        self.assertEqual(len(task.id), 8)

    def test_init_with_params(self):
        task = Task(
            type=TaskType.DEFENSE,
            target="http://example.com",
            modules=["xss", "sqli"],
            priority=TaskPriority.HIGH,
            timeout=600,
        )
        self.assertEqual(task.type, TaskType.DEFENSE)
        self.assertEqual(task.target, "http://example.com")
        self.assertEqual(task.modules, ["xss", "sqli"])
        self.assertEqual(task.priority, TaskPriority.HIGH)
        self.assertEqual(task.timeout, 600)

    def test_start(self):
        task = Task(type=TaskType.ATTACK)
        task.start()
        self.assertEqual(task.status, TaskStatus.RUNNING)
        self.assertIsNotNone(task.started_at)

    def test_succeed(self):
        task = Task(type=TaskType.ATTACK)
        task.start()
        task.succeed({"score": 100})
        self.assertEqual(task.status, TaskStatus.SUCCESS)
        self.assertEqual(task.result, {"score": 100})
        self.assertIsNotNone(task.finished_at)

    def test_fail(self):
        task = Task(type=TaskType.ATTACK)
        task.start()
        task.fail("connection timeout")
        self.assertEqual(task.status, TaskStatus.FAILED)
        self.assertEqual(task.error, "connection timeout")
        self.assertIsNotNone(task.finished_at)

    def test_block(self):
        task = Task(type=TaskType.ATTACK)
        task.block("waiting for dependency")
        self.assertEqual(task.status, TaskStatus.BLOCKED)
        self.assertEqual(task.error, "waiting for dependency")

    def test_to_dict(self):
        task = Task(type=TaskType.ATTACK, target="http://example.com")
        d = task.to_dict()
        self.assertEqual(d["type"], "attack")
        self.assertEqual(d["status"], "pending")
        self.assertEqual(d["target"], "http://example.com")
        self.assertIn("id", d)
        self.assertIn("created_at", d)

    def test_from_dict(self):
        data = {
            "id": "abc12345",
            "type": "defense",
            "status": "success",
            "priority": 2,
            "target": "http://test.com",
            "modules": ["xss"],
            "params": {"verbose": True},
            "depends_on": [],
            "timeout": 600,
            "result": {"score": 90},
            "error": None,
            "created_at": "2026-01-01T00:00:00",
            "started_at": "2026-01-01T00:00:01",
            "finished_at": "2026-01-01T00:00:02",
        }
        task = Task.from_dict(data)
        self.assertEqual(task.id, "abc12345")
        self.assertEqual(task.type, TaskType.DEFENSE)
        self.assertEqual(task.status, TaskStatus.SUCCESS)
        self.assertEqual(task.priority, TaskPriority.HIGH)
        self.assertEqual(task.result, {"score": 90})


class TestTaskResult(unittest.TestCase):
    def test_init(self):
        r = TaskResult(task_id="t1", agent="test", success=True)
        self.assertEqual(r.task_id, "t1")
        self.assertEqual(r.agent, "test")
        self.assertTrue(r.success)
        self.assertEqual(r.duration_ms, 0)

    def test_to_dict(self):
        r = TaskResult(task_id="t1", agent="test", success=True, data={"key": "val"})
        d = r.to_dict()
        self.assertEqual(d["task_id"], "t1")
        self.assertEqual(d["data"], {"key": "val"})

    def test_to_json(self):
        r = TaskResult(task_id="t1", agent="test", success=False, error="fail")
        j = r.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["error"], "fail")
        self.assertFalse(parsed["success"])

    def test_from_dict(self):
        data = {
            "task_id": "t2",
            "agent": "engine",
            "success": True,
            "data": {"result": "ok"},
            "findings": [],
            "events": [],
            "duration_ms": 150,
            "error": None,
            "timestamp": "2026-01-01T00:00:00",
        }
        r = TaskResult.from_dict(data)
        self.assertEqual(r.task_id, "t2")
        self.assertEqual(r.duration_ms, 150)
        self.assertEqual(r.timestamp.year, 2026)


if __name__ == "__main__":
    unittest.main()
