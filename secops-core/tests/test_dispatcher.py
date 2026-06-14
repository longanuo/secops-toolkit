import unittest
from unittest.mock import patch, MagicMock
from secops_core.dispatcher import TaskRouter
from secops_core.task import TaskType, TaskPriority


class TestTaskRouterInit(unittest.TestCase):
    def test_default_init(self):
        router = TaskRouter()
        self.assertIsNotNone(router.registry)
        self.assertEqual(router.max_workers, 4)

    def test_custom_max_workers(self):
        router = TaskRouter(max_workers=8)
        self.assertEqual(router.max_workers, 8)


class TestParseIntent(unittest.TestCase):
    def setUp(self):
        self.router = TaskRouter()

    def test_attack_keywords(self):
        for kw in ["扫描目标", "漏洞检测", "attack target", "scan url", "xss测试"]:
            task_type, _ = self.router._parse_intent(kw)
            self.assertEqual(task_type, TaskType.ATTACK, f"Failed for: {kw}")

    def test_defense_keywords(self):
        for kw in ["系统体检", "一键加固", "check server", "harden system", "防火墙更新"]:
            task_type, _ = self.router._parse_intent(kw)
            self.assertEqual(task_type, TaskType.DEFENSE, f"Failed for: {kw}")

    def test_learn_keywords(self):
        for kw in ["学习github", "learn from repo", "爬取情报"]:
            task_type, _ = self.router._parse_intent(kw)
            self.assertEqual(task_type, TaskType.LEARN, f"Failed for: {kw}")

    def test_hybrid_keywords(self):
        for kw in ["扫描+加固", "全量扫描加固"]:
            task_type, _ = self.router._parse_intent(kw)
            self.assertEqual(task_type, TaskType.HYBRID, f"Failed for: {kw}")

    def test_unknown_defaults_to_defense(self):
        task_type, _ = self.router._parse_intent("随便说点什么")
        self.assertEqual(task_type, TaskType.DEFENSE)


class TestExtractParams(unittest.TestCase):
    def setUp(self):
        self.router = TaskRouter()

    def test_extract_key_value(self):
        params = self.router._extract_params("scan target=http://x.com modules=xss,sqli")
        self.assertEqual(params["target"], "http://x.com")
        self.assertEqual(params["modules"], "xss,sqli")

    def test_no_params(self):
        params = self.router._extract_params("just a normal sentence")
        self.assertEqual(params, {})


class TestParseAndBuild(unittest.TestCase):
    def setUp(self):
        self.router = TaskRouter()

    def test_build_attack_task(self):
        task = self.router.parse_and_build("扫描漏洞 target=http://x.com")
        self.assertEqual(task.type, TaskType.ATTACK)

    def test_build_with_overrides(self):
        task = self.router.parse_and_build(
            "check system",
            target="http://override.com",
            modules=["xss"],
            priority=TaskPriority.CRITICAL,
        )
        self.assertEqual(task.target, "http://override.com")
        self.assertEqual(task.modules, ["xss"])
        self.assertEqual(task.priority, TaskPriority.CRITICAL)


class TestMergeResults(unittest.TestCase):
    def setUp(self):
        self.router = TaskRouter()

    def test_merge_all_success(self):
        from secops_core.result import TaskResult
        r1 = TaskResult(task_id="t1", agent="a1", success=True, data={"k1": "v1"})
        r2 = TaskResult(task_id="t1", agent="a2", success=True, data={"k2": "v2"})
        merged = self.router._merge_results("t1", [r1, r2], 100)
        self.assertTrue(merged.success)
        self.assertEqual(merged.data, {"k1": "v1", "k2": "v2"})

    def test_merge_with_failure(self):
        from secops_core.result import TaskResult
        r1 = TaskResult(task_id="t1", agent="a1", success=True, data={"k1": "v1"})
        r2 = TaskResult(task_id="t1", agent="a2", success=False, error="boom")
        merged = self.router._merge_results("t1", [r1, r2], 100)
        self.assertFalse(merged.success)
        self.assertIn("boom", merged.error)


class TestExecuteNoAgent(unittest.TestCase):
    def test_no_matching_agent(self):
        router = TaskRouter()
        with patch.object(router.registry, "match", return_value=[]):
            from secops_core.task import Task
            task = Task(type=TaskType.ATTACK, target="http://x.com")
            result = router.execute(task)
        self.assertFalse(result.success)
        self.assertIn("No matching agent", result.error)


class TestDefaultRouter(unittest.TestCase):
    def test_default_creates_instance(self):
        router = TaskRouter.default()
        self.assertIsInstance(router, TaskRouter)


class TestGetSystemStatus(unittest.TestCase):
    def test_returns_dict(self):
        router = TaskRouter()
        status = router.get_system_status()
        self.assertIn("uptime_seconds", status)
        self.assertIn("agent_states", status)
        self.assertGreaterEqual(status["uptime_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
