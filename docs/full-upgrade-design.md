# SecOps 全面升级设计方案

> 调度逻辑 + 新增模块 + Agent 通信机制 — 三合一

---

## 第一部分：现状诊断

### 1.1 攻击模块现状

| 模块 | 状态 | 备注 |
|------|------|------|
| 13 个检测器 (XSS/SQLi/SSTI/LFI/SSRF/XXE/RCE/NoSQLi/InfoLeak/JWT/IDOR/CORS/Redirect) | ✅ 完整 | 无 TODO |
| arsenal.py | ⚠️ 仅 4 类 payload | XSS/SQLi/SSRF/RCE，缺 SSTI/LFI/XXE 等 |
| github_offense.py | ⚠️ 12 类但 5 类无映射 | LDAP/CSVi/XPATHi/DirFuzz/FuzzChars 被静默丢弃 |
| browser_engine.py | ✅ SPA 支持 | — |
| auth.py + auth_breaker.py | ✅ 授权门禁 | — |
| 测试覆盖 | ✅ 4 个测试文件 | — |

### 1.2 防御模块现状

| 模块 | 状态 | 备注 |
|------|------|------|
| evaluator.py | ✅ 411 行 | Linux + Windows 双平台 |
| hardener.py | ✅ 402 行 | 8 步 Linux + 5 步 Windows，含回滚 |
| firewall.py | ✅ 135 行 | nftables + Windows FW，3 级降级 |
| threat_intel.py | ✅ 149 行 | 6 源聚合 + 信誉评分 |
| waf.py | ✅ 214 行 | 15 种 WAF 指纹 + 绕过 payload |
| anomaly.py | ⚠️ 仅 3 项检查 | 暴力破解/可疑进程/SSH 密钥，缺更多检测 |
| cron.py | ✅ 164 行 | 多平台 webhook |
| reporter.py | ✅ 155 行 | HTML + Markdown |
| github_intel.py | ✅ 95 行 | IP 情报 + Nginx WAF |
| 测试覆盖 | ⚠️ 缺 reporter 和 github_intel 测试 | — |

### 1.3 核心通信问题（最大痛点）

```
现状：完全隔离

  secops-offense                    secops-defense
  ┌──────────────┐                  ┌──────────────┐
  │ Finding 对象  │   ╳ 无通信  ╳   │  raw dict    │
  │ JSON 报告    │                  │  JSON 报告    │
  │ 本地文件     │                  │  webhook     │
  └──────┬───────┘                  └──────┬───────┘
         │                                 │
         └──────────┐   ┌─────────────────┘
                    ▼   ▼
              secops-cli/main.py
              (唯一集成点，if-else 链)
```

**具体问题：**

| 问题 | 影响 |
|------|------|
| 攻击发现 XSS → 无法自动生成 WAF 规则 | 攻防脱节 |
| 防御发现弱 SSH → 无法告知攻击模块优先测试 | 信息孤岛 |
| 攻击用 `Finding` 类，防御用 `dict` | 数据模型不统一 |
| GitHub 缓存逻辑重复实现两份 | 代码冗余 |
| HTTP 客户端 core 用 urllib，其余用 requests | 不一致 |
| 攻击结果无 webhook 通知 | 告警缺失 |
| 无结构化日志 / 关联 ID | 排查困难 |

---

## 第二部分：调度逻辑优化

### 2.1 新增组件（secops-core 层）

```
secops-core/secops_core/
├── task.py              # Task 数据结构
├── dispatcher.py        # TaskRouter + TaskQueue
├── agent_registry.py    # Agent 注册表
├── result.py            # TaskResult 结构化输出
└── event_bus.py         # 进程内事件总线
```

### 2.2 Task 数据结构

```python
class TaskType(Enum):
    ATTACK = "attack"
    DEFENSE = "defense"
    HYBRID = "hybrid"      # 攻击后自动加固
    LEARN = "learn"         # GitHub 情报学习

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"

@dataclass
class Task:
    id: str                    # UUID 前 8 位
    type: TaskType
    status: TaskStatus
    priority: int              # 0=LOW, 1=NORMAL, 2=HIGH, 3=CRITICAL
    target: str                # URL / 主机
    modules: list              # 指定模块列表
    params: dict               # 额外参数
    depends_on: list           # 前置任务 ID
    timeout: int               # 超时秒数
    result: Optional[dict]
    error: Optional[str]
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
```

### 2.3 AgentRegistry

```python
@dataclass
class AgentRef:
    name: str
    type: TaskType
    capabilities: list          # ["xss", "sqli", "firewall", ...]
    module_path: str            # "secops_offense.attack_engine"
    entry_function: str         # "start_attack"
    priority: int
    max_concurrent: int

class AgentRegistry:
    def auto_register(self):
        # 攻击 Agent
        self.register(AgentRef(
            name="attack_engine",
            type=TaskType.ATTACK,
            capabilities=["xss","sqli","ssti","lfi","ssrf","xxe","rce",
                          "nosqli","infoleak","jwt","idor","cors","redirect"],
            module_path="secops_offense.attack_engine",
            entry_function="start_attack",
            priority=10,
        ))

        # 防御 Agents
        self.register(AgentRef(name="evaluator", type=TaskType.DEFENSE,
            capabilities=["check","evaluator","体检"],
            module_path="secops_defense.evaluator",
            entry_function="run_evaluation", priority=10))

        self.register(AgentRef(name="hardener", type=TaskType.DEFENSE,
            capabilities=["harden","加固"],
            module_path="secops_defense.hardener",
            entry_function="run_hardening", priority=5))

        self.register(AgentRef(name="firewall", type=TaskType.DEFENSE,
            capabilities=["firewall","防火墙"],
            module_path="secops_defense.firewall",
            entry_function="update_threat_intel_firewall", priority=5))

        # ... 更多 agent
```

### 2.4 TaskRouter 调度流程

```
输入文本 / CLI 命令 / Hermes 调用
        │
        ▼
    TaskRouter.route(input)
        │
        ├─ 1. parse_intent(input)
        │     ├─ 关键词匹配: attack keywords → ATTACK
        │     ├─ 关键词匹配: defense keywords → DEFENSE
        │     ├─ 组合关键词: "扫描+加固" → HYBRID
        │     └─ 返回: TaskType + params
        │
        ├─ 2. build_task(type, params)
        │     ├─ 创建 Task 对象
        │     ├─ 设置优先级、超时
        │     └─ 返回: Task
        │
        ├─ 3. registry.match(task)
        │     ├─ 按 type + capabilities 匹配
        │     └─ 返回: [AgentRef, ...]
        │
        ├─ 4. queue.execute(task, agents)
        │     ├─ 并发控制 (max_workers)
        │     ├─ 动态导入 agent 模块
        │     ├─ 调用 entry_function
        │     └─ 返回: [TaskResult, ...]
        │
        └─ 5. aggregate(results)
              ├─ 合并 findings
              ├─ 关联分析
              └─ 返回: TaskResult
```

### 2.5 CLI 改造对比

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
    result = router.route("扫描漏洞 target=" + url)
    print(result)
```

---

## 第三部分：新增模块

### 3.1 攻击模块新增

| 模块 | 类型 | 优先级 | 说明 |
|------|------|--------|------|
| `ldap.py` | 检测器 | P1 | LDAP 注入检测 |
| `csvi.py` | 检测器 | P2 | CSV 注入检测 |
| `xpathi.py` | 检测器 | P2 | XPath 注入检测 |
| `deserialization.py` | 检测器 | P1 | 反序列化漏洞检测 |
| `subdomain_takeover.py` | 检测器 | P2 | 子域名接管检测 |
| `crlf.py` | 检测器 | P2 | CRLF 注入检测 |
| `cache_poisoning.py` | 检测器 | P3 | Web 缓存投毒检测 |

**arsenal.py 扩展：** 从 4 类 → 10 类 payload，补充 SSTI/LFI/XXE/NoSQLi/JWT/Deserialization

**github_offense.py 修复：** 补全 LDAP/CSVi/XPATHi 的 category 映射

### 3.2 防御模块新增

| 模块 | 类型 | 优先级 | 说明 |
|------|------|--------|------|
| `tls_audit.py` | 新增 | P1 | TLS 证书审计（过期/弱密码套件/TLS 版本） |
| `rootkit_check.py` | 新增 | P1 | Rootkit/后门检测（隐藏进程/ld.so.preload/内核模块） |
| `fim.py` | 新增 | P2 | 文件完整性监控（基于哈希的变更检测） |
| `remediation.py` | 新增 | P1 | 自动修复反馈（攻击发现 → 生成防御规则） |
| `log_analyzer.py` | 新增 | P2 | 日志分析（Nginx/Apache 异常请求模式） |

### 3.3 攻防联动模块（核心新增）

```python
# remediation.py — 攻击→防御 自动转化

class RemediationEngine:
    """根据攻击 findings 自动生成防御规则"""

    def generate_waf_rules(self, findings: list) -> dict:
        """XSS/SQLi findings → Nginx/ModSecurity WAF 规则"""
        rules = {"nginx": [], "modsecurity": []}
        for f in findings:
            if f.vuln_type == "xss":
                rules["nginx"].append(self._xss_to_nginx(f))
            elif f.vuln_type == "sqli":
                rules["modsecurity"].append(self._sqli_to_modsec(f))
        return rules

    def generate_fail2ban_filters(self, findings: list) -> dict:
        """扫描行为 findings → fail2ban 过滤规则"""

    def generate_iptables_rules(self, findings: list) -> dict:
        """恶意 IP findings → nftables 封禁规则"""

    def suggest_hardening(self, findings: list) -> list:
        """综合 findings → 加固建议列表"""
```

---

## 第四部分：Agent 通信机制

### 4.1 共享数据模型（secops-core 新增）

```python
# security_event.py

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SecurityEvent:
    """统一安全事件 — 攻防共用"""
    id: str
    timestamp: datetime
    source: str              # "attack_engine" / "evaluator" / "anomaly"
    event_type: str          # "vuln_found" / "config_weak" / "anomaly_detected"
    severity: Severity
    category: str            # "xss" / "sqli" / "ssh_config" / ...
    title: str
    description: str
    location: str            # URL / 文件路径 / IP
    evidence: str
    remediation: str
    metadata: dict           # 可扩展字段

    def to_dict(self) -> dict: ...
    def to_json(self) -> str: ...

    @classmethod
    def from_finding(cls, finding) -> 'SecurityEvent':
        """从攻击 Finding 对象转换"""
        ...

    @classmethod
    def from_scan_data(cls, scan_data: dict) -> list['SecurityEvent']:
        """从防御 scan_data 转换"""
        ...
```

### 4.2 事件总线（进程内 pub/sub）

```python
# event_bus.py

class EventBus:
    """进程内事件总线 — 解耦攻防模块"""

    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(self, event_type: str, handler: Callable):
        """订阅事件"""
        self._subscribers.setdefault(event_type, []).append(handler)

    def publish(self, event_type: str, data: Any):
        """发布事件"""
        for handler in self._subscribers.get(event_type, []):
            try:
                handler(data)
            except Exception as e:
                log.error(f"Event handler error: {e}")

    def clear(self):
        self._subscribers.clear()

# 全局单例
bus = EventBus()
```

### 4.3 攻防联动事件流

```
攻击发现 XSS 漏洞
    │
    ▼
AttackEngine → SecurityEvent(type="vuln_found", category="xss")
    │
    ▼
EventBus.publish("vuln_found", event)
    │
    ├──→ RemediationEngine.on_vuln_found(event)
    │       ├─ 生成 Nginx WAF 规则
    │       ├─ 生成 fail2ban 过滤器
    │       └─ 输出: remediation.json
    │
    ├──→ AlertManager.on_vuln_found(event)
    │       └─ 发送 webhook 到飞书/钉钉/企微
    │
    └──→ ReportCollector.on_vuln_found(event)
            └─ 收集到统一报告
```

### 4.4 修复后的数据流

```
之前：完全隔离
  offense ─╳─ defense

之后：事件驱动联动
  offense → SecurityEvent → EventBus ──→ defense (自动生成规则)
                               │
                               └──────→ alert (webhook 通知)
                               └──────→ report (统一报告)
```

### 4.5 统一 HTTP 客户端

```python
# secops-core/http_client.py 改造

import requests
from .config import HTTP_TIMEOUT, get_proxies

def http_get(url, **kwargs):
    """统一 HTTP GET — 替换分散的 requests 调用"""
    kwargs.setdefault("timeout", HTTP_TIMEOUT)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("proxies", get_proxies())
    resp = requests.get(url, **kwargs)
    return resp.status_code, dict(resp.headers), resp.text

def http_post(url, **kwargs):
    """统一 HTTP POST"""
    ...
```

**迁移清单：** 将以下文件中的裸 `requests` 调用替换为 core http_client：
- `secops-offense/online_scanner.py`
- `secops-offense/github_offense.py`
- `secops-defense/waf.py`
- `secops-defense/threat_intel.py`
- `secops-defense/cron.py`
- `secops-defense/github_intel.py`

### 4.6 GitHub 缓存统一

```python
# secops-core/github_client.py 改造

class GitHubClient:
    """统一 GitHub 客户端 — 合并 core + offense 重复逻辑"""

    def fetch_with_cache(self, owner, repo, path, ttl_hours=24):
        """带缓存的 raw content 获取"""
        cache_key = self._cache_key(owner, repo, path)
        if self._is_cache_valid(cache_key, ttl_hours):
            return self._load_cache(cache_key)
        content = self._fetch_raw(owner, repo, path)
        self._save_cache(cache_key, content)
        return content

# offense 模块改为:
from secops_core.github_client import GitHubClient
client = GitHubClient()
payloads = client.fetch_with_cache("swisskyrepo", "PayloadsAllTheThings", "...")
```

### 4.7 结构化日志

```python
# secops-core/logger.py 改造

import json
from datetime import datetime
from contextvars import ContextVar

# 请求级关联 ID
correlation_id: ContextVar[str] = ContextVar('correlation_id', default='')

class StructuredFormatter:
    """JSON 结构化日志格式"""
    def format(self, record):
        return json.dumps({
            "ts": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "corr_id": correlation_id.get(),
            "msg": record.getMessage(),
        }, ensure_ascii=False)

def get_logger(name: str):
    """返回带关联 ID 的结构化 logger"""
    ...
```

---

## 第五部分：Hermes Skill 升级

### 5.1 YAML 格式扩展

**改造前 (offense.yaml):**
```yaml
triggers:
  - "扫描漏洞"
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
  - "攻击测试"

agent:
  name: attack_engine
  type: attack
  capabilities: [xss, sqli, ssti, lfi, ssrf, xxe, rce, nosqli, infoleak, jwt, idor, cors, redirect]
  entry: secops_offense.attack_engine:start_attack
  timeout: 300
  priority: 10

events:
  subscribe:
    - vuln_found
  publish:
    - attack_complete

remediation:
  auto_generate: true
  targets: [waf_rules, fail2ban, iptables]
```

### 5.2 调度链升级

```
旧链路:
[用户请求] → [Hermes Agent] → [模式识别] → [skill] → [JSON输出]

新链路:
[用户请求] → [Hermes Agent] → [TaskRouter] → [AgentRegistry.match]
                                                    │
                                                    ├─→ [AttackAgent.execute]
                                                    │       │
                                                    │       ▼
                                                    │   [EventBus.publish]
                                                    │       │
                                                    │       ├─→ [RemediationEngine]
                                                    │       ├─→ [AlertManager]
                                                    │       └─→ [ReportCollector]
                                                    │
                                                    └─→ [DefenseAgent.execute]
                                                            │
                                                            ▼
                                                        [TaskResult聚合]
```

---

## 第六部分：文件变更总清单

### 新增文件 (secops-core)

| 文件 | 说明 | 预估行数 |
|------|------|----------|
| `task.py` | Task 数据结构 | ~80 |
| `dispatcher.py` | TaskRouter + TaskQueue | ~200 |
| `agent_registry.py` | Agent 注册表 | ~100 |
| `result.py` | TaskResult 数据结构 | ~50 |
| `event_bus.py` | 进程内事件总线 | ~60 |
| `security_event.py` | 统一安全事件模型 | ~120 |
| `tests/test_dispatcher.py` | 调度器测试 | ~100 |

### 新增文件 (secops-offense)

| 文件 | 说明 | 预估行数 |
|------|------|----------|
| `modules/ldap.py` | LDAP 注入检测器 | ~80 |
| `modules/deserialization.py` | 反序列化检测器 | ~80 |
| `modules/crlf.py` | CRLF 注入检测器 | ~60 |
| `modules/subdomain_takeover.py` | 子域名接管检测器 | ~100 |

### 新增文件 (secops-defense)

| 文件 | 说明 | 预估行数 |
|------|------|----------|
| `tls_audit.py` | TLS 证书审计 | ~120 |
| `rootkit_check.py` | Rootkit 检测 | ~100 |
| `remediation.py` | 攻击→防御转化引擎 | ~150 |
| `tests/test_tls_audit.py` | TLS 审计测试 | ~50 |
| `tests/test_remediation.py` | 转化引擎测试 | ~80 |

### 修改文件

| 文件 | 改动 |
|------|------|
| `secops-core/http_client.py` | 统一为 requests，加入代理支持 |
| `secops-core/logger.py` | 结构化日志 + 关联 ID |
| `secops-core/github_client.py` | 合并 offense 重复缓存逻辑 |
| `secops-cli/main.py` | 改为调用 TaskRouter |
| `hermes-skills/offense.yaml` | 补充 agent/events/remediation 配置 |
| `hermes-skills/defense.yaml` | 补充 agent/events 配置 |
| `secops-offense/github_offense.py` | 补全 LDAP/CSVi/XPATHi 映射 |
| `secops-offense/arsenal.py` | 扩展到 10 类 payload |

---

## 第七部分：实施计划

### Phase 1: 基础设施 (Day 1-2)
- [ ] `task.py` + `result.py` + `security_event.py`
- [ ] `event_bus.py`
- [ ] `http_client.py` 统一改造
- [ ] `logger.py` 结构化改造

### Phase 2: 调度器 (Day 3-4)
- [ ] `agent_registry.py`
- [ ] `dispatcher.py` (TaskRouter + TaskQueue)
- [ ] 单元测试
- [ ] CLI 集成

### Phase 3: 攻防联动 (Day 5-6)
- [ ] `remediation.py` (攻击→防御转化)
- [ ] 攻击模块 findings → SecurityEvent 转换
- [ ] EventBus 集成到 AttackEngine
- [ ] 自动 WAF 规则生成

### Phase 4: 新增攻击模块 (Day 7-8)
- [ ] LDAP 注入检测器
- [ ] 反序列化检测器
- [ ] CRLF 注入检测器
- [ ] 子域名接管检测器
- [ ] arsenal.py 扩展
- [ ] github_offense.py 映射修复

### Phase 5: 新增防御模块 (Day 9-10)
- [ ] TLS 证书审计
- [ ] Rootkit 检测
- [ ] Hermes skill YAML 升级
- [ ] 端到端测试

---

## 第八部分：风险评估

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| 动态导入性能 | 低 | 低 | 模块级缓存 |
| EventBus 事件丢失 | 低 | 中 | 同步调用 + 异常兜底 |
| 现有模块接口不兼容 | 低 | 高 | 先读源码确认，保留 fallback |
| 并发资源竞争 | 中 | 中 | max_workers + 锁 |
| 改动范围大引入 bug | 中 | 高 | 分阶段实施 + 每阶段测试 |
