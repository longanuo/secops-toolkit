# Mimocode Agent 集成规范

## 架构概览

```
[用户请求]
    ↓
[Mimocode Agent 调度器]
    ↓ 识别任务类型
[cybersecurity-ops skill]
    ↓ 执行任务
[结构化JSON输出] ← 供 habit 学习引擎消费
    ↓
[Mimocode 记忆系统]
    ↓ (projects/MEMORY.md + sessions/checkpoint.md)
[下次调用时偏好注入]
```

---

## 与 Mimocode Memory 系统的集成

### 记忆层级

| 层级 | 文件路径 | 用途 |
|------|---------|------|
| 项目记忆 | `~/.mimocode/memory/projects/<project>/MEMORY.md` | 项目级规则、架构决策、持久化知识 |
| 会话记忆 | `~/.mimocode/memory/sessions/<sid>/checkpoint.md` | 当前会话状态、任务进度、工作流模式 |
| 全局记忆 | `~/.mimocode/memory/global/MEMORY.md` | 用户偏好、跨项目习惯 |

### 自动学习数据结构

每次 skill 执行后，Mimocode agent 应更新以下记忆：

```json
{
  "type": "learning",
  "scope": "project",
  "key": "secops-workflow-pattern",
  "body": "## Workflow Pattern\n- Mode: competition/web\n- Tools: burpsuite, sqlmap, dirsearch\n- Steps: [dirscan, intercept, sqli_test, payload_craft]\n- Success rate: 85%\n- Avg time: 45min"
}
```

### 偏好注入机制

Mimocode agent 在调用 skill 时，自动从 MEMORY.md 读取用户偏好并注入到上下文：

```python
# Mimocode 自动注入的上下文
skill_context = {
    "user_skill_level": "intermediate",  # 从 MEMORY.md 读取
    "preferred_tools": ["nmap", "sqlmap"],  # 从 workflow_history 提取
    "recent_corrections": ["不要用 sqlmap 自动化，手动验证更重要"],  # 从 notes.md 读取
    "firewall_config": {"open_ports": [22, 80, 443]},  # 从 project memory 读取
}
```

---

## 统一输出 Schema（所有模式共用）

每次 skill 执行结束，**必须**输出一个符合此 schema 的 JSON 块（放在文本回复末尾，用代码块包裹）：

```json
{
  "$schema": "cybersecurity-ops/v1",
  "skill": "cybersecurity-ops",
  "mode": "competition|server-ops|sandbox-testing|github-intel|firewall|vuln-scan|health-check|hardening",
  "task_id": "<mode>-<YYYYMMDD>-<三位序号，如001>",
  "session_context": {
    "user_goal": "<一句话描述用户目标>",
    "environment": "<本地/沙盒/生产服务器/靶机>",
    "authorized_scope": "<明确描述授权范围>"
  },
  "status": "completed|in_progress|needs_input|failed",
  "execution": {
    "steps_taken": ["<步骤1>", "<步骤2>"],
    "commands_run": ["<命令1>"],
    "duration_seconds": 0
  },
  "artifacts": [
    {
      "type": "rule|script|report|config|writeup|log",
      "path": "<文件路径>",
      "description": "<说明>",
      "auto_apply": false
    }
  ],
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "<类别>",
      "description": "<发现>",
      "recommendation": "<建议>"
    }
  ],
  "habit_hints": {
    "task_category": "<细分类别>",
    "preferred_tools": ["<工具>"],
    "workflow_pattern": "<解决路径的描述>",
    "time_spent_min": 0,
    "difficulty": "easy|medium|hard",
    "success": true,
    "user_corrections": [],
    "custom_preferences": {}
  },
  "next_actions": ["<建议后续步骤>"],
  "tags": ["<关键词，用于habit检索索引>"]
}
```

---

## 工具调用接口设计（供 Mimocode agent 实现）

### 可供调用的函数签名

```python
# 竞赛模式
def solve_ctf_challenge(
    challenge_type: str,      # web|pwn|reverse|crypto|forensics|misc
    challenge_url: str = "",  # Web题目URL
    file_path: str = "",      # 二进制/附件路径
    description: str = "",    # 题目描述
    hints: list = []
) -> dict:                    # 返回标准JSON输出

# 漏洞扫描
def scan_vulnerabilities(
    target_url: str,
    modules: list = ["xss", "sqli", "ssrf", "xxe", "rce", "nosqli", "ssti", "lfi", "infoleak"],
    params: dict = {}
) -> dict:

# 服务器运维
def server_health_check(
    server_id: str,
    check_type: str = "full",  # full|quick|incident
    log_paths: list = ["/var/log/auth.log", "/var/log/syslog"]
) -> dict:

# 沙盒测试
def sandbox_test(
    test_type: str,           # stability|vuln_repro|ctf_env
    target_image: str,
    test_duration_min: int = 10,
    resource_limits: dict = {"cpu": "1", "memory": "512m"}
) -> dict:

# 情报学习
def learn_from_github(
    repos: list,              # 仓库列表
    extract_rules: bool = True,
    apply_to_firewall: bool = False  # 谨慎：自动应用时先测试
) -> dict:

# 防火墙优化
def update_firewall(
    action: str,              # add_rules|remove_rules|full_update|audit
    intel_file: str = "",
    manual_rules: list = []
) -> dict:

# 系统安全体检
def run_health_check(
    check_type: str = "full",  # full|quick|custom
    modules: list = ["accounts", "ssh", "services", "ports", "files"]
) -> dict:

# 安全加固
def run_hardening(
    target_os: str = "linux",  # linux|windows
    modules: list = ["ssh", "password", "sysctl", "fail2ban", "auditd"]
) -> dict:
```

---

## Mimocode 记忆更新钩子

每次任务完成后，Mimocode agent 应执行以下更新逻辑：

### 1. 更新项目记忆 (MEMORY.md)

```python
# 自动追加到 MEMORY.md 的 ## Discovered durable knowledge 部分
memory_entry = f"""
## [任务 {task_id}] {timestamp}
- **模式**: {mode}
- **发现**: {summary}
- **工具偏好**: {preferred_tools}
- **工作流**: {workflow_pattern}
"""
```

### 2. 更新会话检查点 (checkpoint.md)

```
## §4 Task Tree
- T{n}: {task_summary} - {status}

## §5 Current Work
- 正在执行: {current_step}
- 下一步: {next_step}
```

### 3. 记录用户纠错 (notes.md)

```python
# 如果用户修正了工具选择或工作流
notes_entry = f"""
## [turn {n} · {timestamp}]
用户纠正: {correction_detail}
原因: {reason}
后续应: {improved_approach}
"""
```

---

## 多步骤任务链示例

**场景：从GitHub学习漏洞 → 沙盒复现 → 提取防御规则 → 更新防火墙**

```
Step 1: learn_from_github(["vulhub/vulhub"], extract_rules=True)
  → 产出: CVE详情, 攻击特征, 临时规则草稿
  → 记忆更新: projects/MEMORY.md 追加 CVE-2024-xxxx 学习记录

Step 2: sandbox_test(test_type="vuln_repro", target_image="vulhub/xxxx")
  → 产出: 复现确认, 网络流量特征, 防御验证
  → 记忆更新: checkpoint.md 更新任务进度

Step 3: update_firewall(action="add_rules", manual_rules=[从Step1提取的规则])
  → 产出: 规则添加确认, 防火墙状态
  → 记忆更新: projects/MEMORY.md 追加防火墙规则变更

Step 4: [Mimocode session checkpoint]
  → 记录: 完整工作流耗时、规则来源、成功状态
  → 下次遇到相同CVE类型时，自动推荐此工作流
```

---

## 错误处理规范

```json
{
  "skill": "cybersecurity-ops",
  "status": "failed",
  "error": {
    "code": "AUTH_VIOLATION|SANDBOX_ESCAPE|TOOL_NOT_FOUND|NETWORK_ERROR",
    "message": "<错误描述>",
    "recovery": "<恢复建议>"
  },
  "habit_hints": {
    "failure_reason": "<失败原因>",
    "user_corrections": ["<需要用户修正的地方>"]
  }
}
```

**错误代码说明：**
- `AUTH_VIOLATION`：检测到操作超出授权范围，任务中止
- `SANDBOX_ESCAPE`：沙盒容器尝试访问宿主网络，立即隔离
- `TOOL_NOT_FOUND`：所需工具未安装，提供安装命令
- `NETWORK_ERROR`：GitHub/外部资源访问失败，提供离线替代方案

---

## Mimocode 特有优势

相比传统 Agent 框架，Mimocode 提供：

1. **持久化记忆系统**：跨会话保持学习成果，无需手动维护 habit 文件
2. **文件系统直接访问**：可直接读写项目文件、执行命令
3. **多层级记忆**：项目/会话/全局三层记忆，精细化管理偏好
4. **自主探索**：可主动搜索代码库、分析漏洞模式
5. **实时交互**：支持多轮迭代优化，根据用户反馈调整策略
