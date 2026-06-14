# 调度逻辑优化设计方案

## 1. 现状分析

### 当前架构
```
secops-cli/main.py (CLI入口)
    ├─ argparse 命令行参数
    ├─ 交互式菜单 (if-else 链)
    └─ 直接 import 各模块
        ├─ secops_offense.attack_engine
        ├─ secops_offense.arsenal
        ├─ secops_defense.evaluator
        ├─ secops_defense.hardener
        └─ secops_defense.firewall

hermes-skills/
    ├─ offense.yaml (触发词 → 模块映射)
    └─ defense.yaml (触发词 → 模块映射)
```

### 存在的问题
| 问题 | 影响 |
|------|------|
| CLI 是 if-else 链 | 每增加功能必须改 main.py，违反开闭原则 |
| 无统一任务调度器 | 无法并行执行多模块，无法管理任务依赖 |
| Hermes skill 只是静态定义 | 没有运行时 agent 协调能力 |
| 无状态管理 | 任务执行失败无法重试，无法追踪进度 |
| 模块硬编码 | 攻防选择不灵活，无法动态组合 |
| 无结果聚合 | 多模块结果分散，无法统一分析 |

---

## 2. 目标架构

### 2.1 核心抽象层 (secops-core 新增)

```
secops-core/
├── task.py              # Task 数据结构
├── dispatcher.py        # 任务路由器 + 队列
├── agent_registry.py    # Agent 注册表
└── result.py            # 结果聚合器
```

### 2.2 整体流程

```
用户输入 / Hermes 调用 / CLI 命令
        │
        ▼
    TaskRouter
        │
        ├─ 1. 意图解析 (parse_intent)
        │     ├─ 关键词匹配
        │     ├─ 上下文分析
        │     └─ 输出: TaskType (ATTACK / DEFENSE / HYBRID)
        │
        ├─ 2. 任务构建 (build_task)
        │     ├─ 生成 Task 对象
        │     ├─ 设置优先级、超时、依赖
        │     └─ 输出: Task
        │
        ├─ 3. Agent 匹配 (match_agent)
        │     ├─ 查询 AgentRegistry
        │     ├─ 匹配能力标签
        │     └─ 输出: AgentRef
        │
        ├─ 4. 任务分发 (dispatch)
        │     ├─ 加入 TaskQueue
        │     ├─ 并发/串行调度
        │     └─ 执行 agent.execute(task)
        │
        └─ 5. 结果聚合 (aggregate)
              ├─ 收集各 agent 结果
              ├─ 去重、排序、关联分析
              └─ 输出: TaskResult
```

---

## 3. 数据结构设计

### 3.1 Task

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
import uuid
from datetime import datetime

class TaskType(Enum):
    ATTACK = "attack"        # 纯攻击任务
    DEFENSE = "defense"      # 纯防御任务
    HYBRID = "hybrid"        # 攻防结合（如：攻击后自动加固）
    LEARN = "learn"          # 学习任务（GitHub情报）

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3

@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: TaskType = TaskType.ATTACK
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.NORMAL

    # 任务参数
    target: str = ""               # 目标 URL / 主机
    modules: list = field(default_factory=list)  # 指定模块列表
    params: dict = field(default_factory=dict)   # 额外参数

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    timeout: int = 300             # 超时秒数

    # 依赖
    depends_on: list = field(default_factory=list)  # 前置任务 ID

    # 结果
    result: Optional[dict] = None
    error: Optional[str] = None
```

### 3.2 AgentRef

```python
@dataclass
class AgentRef:
    name: str
    type: TaskType                  # 支持的任务类型
    capabilities: list              # 能力标签: ["xss", "sqli", "firewall", ...]
    module_path: str                # Python 模块路径
    entry_function: str             # 入口函数名
    priority: int = 0               # 同类 agent 优先级
    max_concurrent: int = 1         # 最大并发数
```

### 3.3 TaskResult

```python
@dataclass
class TaskResult:
    task_id: str
    agent_name: str
    status: TaskStatus
    findings: list = field(default_factory=list)   # 发现的漏洞/问题
    actions_taken: list = field(default_factory=list)  # 已执行的操作
    score: Optional[int] = None     # 安全评分（防御任务）
    duration: float = 0.0
    metadata: dict = field(default_factory=dict)
```

---

## 4. 核心组件设计

### 4.1 TaskRouter

```python
class TaskRouter:
    """任务路由器 - 从输入到任务分发的全流程"""

    def __init__(self, registry: AgentRegistry, queue: TaskQueue):
        self.registry = registry
        self.queue = queue

    def route(self, user_input: str) -> TaskResult:
        """主入口：解析输入 → 构建任务 → 分发 → 返回结果"""
        # 1. 解析意图
        task_type, params = self.parse_intent(user_input)

        # 2. 构建任务
        task = self.build_task(task_type, params)

        # 3. 匹配 Agent
        agents = self.registry.match(task)

        # 4. 分发执行
        results = self.queue.execute(task, agents)

        # 5. 聚合结果
        return self.aggregate(results)

    def parse_intent(self, text: str) -> tuple:
        """意图解析 - 关键词 + 上下文"""
        keywords_attack = ["扫描", "漏洞", "渗透", "攻击", "payload", "xss", "sqli"]
        keywords_defense = ["体检", "加固", "防火墙", "巡检", "威胁", "防御"]
        keywords_learn = ["学习", "github", "情报", "更新"]

        # ... 匹配逻辑
```

### 4.2 AgentRegistry

```python
class AgentRegistry:
    """Agent 注册表 - 管理所有可用的子智能体"""

    def __init__(self):
        self._agents: dict[str, AgentRef] = {}

    def register(self, agent: AgentRef):
        """注册 Agent"""
        self._agents[agent.name] = agent

    def match(self, task: Task) -> list[AgentRef]:
        """根据任务匹配合适的 Agent"""
        matches = []
        for agent in self._agents.values():
            if agent.type == task.type or agent.type == TaskType.HYBRID:
                # 检查能力标签是否覆盖任务所需模块
                if not task.modules or set(task.modules) <= set(agent.capabilities):
                    matches.append(agent)
        return sorted(matches, key=lambda a: -a.priority)

    def auto_register(self):
        """自动注册内置 Agent"""
        self.register(AgentRef(
            name="attack_engine",
            type=TaskType.ATTACK,
            capabilities=["xss", "sqli", "ssti", "lfi", "ssrf", "xxe",
                          "rce", "nosqli", "infoleak", "jwt", "idor",
                          "cors", "redirect"],
            module_path="secops_offense.attack_engine",
            entry_function="start_attack",
            priority=10,
        ))
        self.register(AgentRef(
            name="defense_evaluator",
            type=TaskType.DEFENSE,
            capabilities=["check", "evaluator", "体检"],
            module_path="secops_defense.evaluator",
            entry_function="run_evaluation",
            priority=10,
        ))
        self.register(AgentRef(
            name="defense_hardener",
            type=TaskType.DEFENSE,
            capabilities=["harden", "加固"],
            module_path="secops_defense.hardener",
            entry_function="run_hardening",
            priority=5,
        ))
        # ... 更多 agent
```

### 4.3 TaskQueue

```python
class TaskQueue:
    """任务队列 - 管理并发执行"""

    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self._running: dict[str, Task] = {}
        self._completed: dict[str, TaskResult] = {}

    def execute(self, task: Task, agents: list[AgentRef]) -> list[TaskResult]:
        """执行任务（支持多 agent 并行）"""
        results = []
        for agent in agents:
            # 检查并发限制
            if len(self._running) >= self.max_workers:
                self._wait_for_slot()

            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            self._running[task.id] = task

            try:
                result = self._run_agent(task, agent)
                results.append(result)
            except Exception as e:
                results.append(TaskResult(
                    task_id=task.id,
                    agent_name=agent.name,
                    status=TaskStatus.FAILED,
                    error=str(e),
                ))
            finally:
                self._running.pop(task.id, None)
                task.status = TaskStatus.SUCCESS
                task.finished_at = datetime.now()

        return results

    def _run_agent(self, task: Task, agent: AgentRef) -> TaskResult:
        """动态导入并执行 Agent"""
        import importlib
        module = importlib.import_module(agent.module_path)
        func = getattr(module, agent.entry_function)
        # ... 执行并包装结果
```

---

## 5. 与现有代码的集成

### 5.1 CLI 改造 (secops-cli/main.py)

**改造前:**
```python
elif choice == "1":
    from secops_offense.attack_engine import start_attack
    start_attack()
```

**改造后:**
```python
elif choice == "1":
    from secops_core.dispatcher import TaskRouter
    router = TaskRouter.default()
    result = router.route("扫描漏洞 target_url=" + url)
    print_result(result)
```

### 5.2 Hermes Skill 改造

**改造前 (offense.yaml):**
```yaml
triggers:
  - "扫描漏洞"
  - "渗透测试"
modules:
  - name: attack_engine
    usage: |
      from secops_offense.attack_engine import AttackEngine
```

**改造后 (offense.yaml):**
```yaml
triggers:
  - "扫描漏洞"
  - "渗透测试"
agent:
  name: attack_engine
  type: attack
  capabilities: [xss, sqli, ssti, lfi, ssrf, xxe, rce, nosqli, infoleak, jwt, idor, cors, redirect]
  entry: secops_offense.attack_engine:start_attack
  timeout: 300
  priority: 10
```

### 5.3 攻防联动 (HYBRID 任务)

```python
# 示例：攻击发现漏洞后自动加固
def auto_harden_after_attack(target_url: str):
    router = TaskRouter.default()

    # 1. 先攻击
    attack_task = Task(
        type=TaskType.ATTACK,
        target=target_url,
        modules=["xss", "sqli", "ssti"],
    )
    attack_result = router.execute(attack_task)

    # 2. 根据攻击结果自动加固
    if attack_result.findings:
        harden_task = Task(
            type=TaskType.DEFENSE,
            target=target_url,
            params={"findings": attack_result.findings},
            depends_on=[attack_task.id],
        )
        return router.execute(harden_task)
```

---

## 6. 文件变更清单

| 操作 | 文件路径 | 说明 |
|------|----------|------|
| 新增 | `secops-core/secops_core/task.py` | Task 数据结构 |
| 新增 | `secops-core/secops_core/dispatcher.py` | TaskRouter + TaskQueue |
| 新增 | `secops-core/secops_core/agent_registry.py` | Agent 注册表 |
| 新增 | `secops-core/secops_core/result.py` | TaskResult 数据结构 |
| 修改 | `secops-cli/secops_cli/main.py` | CLI 改为调用 dispatcher |
| 修改 | `hermes-skills/offense.yaml` | 补充 agent 配置 |
| 修改 | `hermes-skills/defense.yaml` | 补充 agent 配置 |
| 新增 | `secops-core/tests/test_dispatcher.py` | 调度器单元测试 |

---

## 7. 兼容性保证

1. **向后兼容**: 现有 `from secops_offense.attack_engine import start_attack` 调用方式不变
2. **渐进迁移**: dispatcher 是新增层，不修改现有模块接口
3. **CLI 双模式**: 交互式菜单和命令行参数都走 dispatcher
4. **Hermes 兼容**: YAML 格式扩展，旧格式仍可解析

---

## 8. 风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| 动态导入性能开销 | 低 | 低 | 模块级缓存 + lazy import |
| 并发执行资源竞争 | 中 | 中 | max_workers 限制 + 锁机制 |
| 现有模块接口不兼容 | 低 | 高 | 先读源码确认接口，保留 fallback |
| 测试覆盖不足 | 中 | 中 | 每个组件配套单元测试 |

---

## 9. 实施步骤

### Phase 1: 数据结构 (Day 1)
- [ ] 实现 Task, TaskResult, AgentRef 数据类
- [ ] 编写单元测试

### Phase 2: 核心调度 (Day 2-3)
- [ ] 实现 AgentRegistry + auto_register
- [ ] 实现 TaskQueue + 并发控制
- [ ] 实现 TaskRouter + parse_intent
- [ ] 集成测试

### Phase 3: CLI 集成 (Day 4)
- [ ] 改造 main.py 调用 dispatcher
- [ ] 保持向后兼容
- [ ] 端到端测试

### Phase 4: Hermes 集成 (Day 5)
- [ ] 更新 YAML skill 定义
- [ ] 测试 Hermes Agent 调度流程
