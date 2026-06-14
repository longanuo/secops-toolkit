# Hermes Agent 集成规范

## 架构概览

```
[用户请求]
    ↓
[Hermes Agent 调度器]
    ↓ 识别任务类型
[cybersecurity-ops skill]
    ↓ 执行任务
[结构化JSON输出] ← 供habit学习引擎消费
    ↓
[Hermes 记忆更新]
    ↓
[下次调用时偏好注入]
```

---

## 统一输出 Schema（所有模式共用）

每次skill执行结束，**必须**输出一个符合此 schema 的 JSON 块（放在文本回复末尾，用代码块包裹）：

```json
{
  "$schema": "cybersecurity-ops/v1",
  "skill": "cybersecurity-ops",
  "mode": "competition|server-ops|sandbox-testing|github-intel|firewall",
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

## Habit Learning 数据结构

Hermes agent 的习惯学习引擎应维护以下持久化数据结构：

### 用户习惯配置文件（user_habits.json）
```json
{
  "user_profile": {
    "skill_level": "beginner|intermediate|advanced",
    "primary_focus": ["competition", "server-ops"],
    "preferred_os": "ubuntu|debian|kali",
    "firewall_solution": "nftables|iptables|none"
  },
  "tool_preferences": {
    "competition": {
      "web": ["burpsuite", "sqlmap", "gobuster"],
      "pwn": ["pwntools", "gdb+pwndbg"],
      "reverse": ["ghidra", "gdb"],
      "crypto": ["pycryptodome", "rsactftool"],
      "forensics": ["volatility3", "wireshark", "binwalk"]
    },
    "server_ops": {
      "monitoring": ["htop", "netdata"],
      "log_analysis": ["grep+awk", "journalctl"],
      "hardening": ["lynis", "fail2ban"]
    }
  },
  "workflow_patterns": [
    {
      "task_type": "web_ctf",
      "typical_steps": ["dirsearch", "burpsuite_intercept", "sqlmap", "payload_craft"],
      "avg_time_min": 45,
      "success_rate": 0.7
    }
  ],
  "firewall_config": {
    "admin_ips": ["<你的管理IP>"],
    "open_ports": [80, 443, 22222],
    "intel_sources": ["stamparm/ipsum"],
    "update_frequency": "daily",
    "crowdsec_enabled": true
  },
  "learning_history": [
    {
      "date": "YYYY-MM-DD",
      "source": "github_repo",
      "topic": "CVE-XXXX-XXXX",
      "defense_rules_generated": 3,
      "applied": true
    }
  ],
  "last_updated": "<ISO时间戳>"
}
```

---

## 工具调用接口设计（供Hermes agent实现）

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
    """调用skill的竞赛解题流程"""

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
```

---

## Hermes Agent 记忆更新钩子

每次任务完成后，Hermes agent 应执行以下更新逻辑：

```python
def update_habits(task_output: dict, user_habits: dict) -> dict:
    """
    根据本次任务输出更新用户习惯记录
    """
    hints = task_output.get("habit_hints", {})
    mode = task_output.get("mode")
    
    # 1. 更新工具偏好（如果用户修正了工具选择，记录新偏好）
    if hints.get("preferred_tools"):
        if mode in user_habits["tool_preferences"]:
            # 将本次使用的工具权重提升
            for tool in hints["preferred_tools"]:
                tools = user_habits["tool_preferences"][mode]
                if isinstance(tools, dict):
                    # 按子类型更新
                    task_cat = hints.get("task_category", "general")
                    if task_cat not in tools:
                        tools[task_cat] = []
                    if tool not in tools[task_cat]:
                        tools[task_cat].insert(0, tool)  # 最近使用的放最前
    
    # 2. 更新工作流模式
    if hints.get("workflow_pattern") and hints.get("success"):
        pattern = {
            "task_type": f"{mode}_{hints.get('task_category', 'general')}",
            "pattern": hints["workflow_pattern"],
            "avg_time_min": hints.get("time_spent_min", 0),
            "difficulty": hints.get("difficulty", "medium")
        }
        # 添加到工作流历史
        if "workflow_history" not in user_habits:
            user_habits["workflow_history"] = []
        user_habits["workflow_history"].append(pattern)
    
    # 3. 用户纠错记录（用于主动避免错误）
    if hints.get("user_corrections"):
        if "corrections_log" not in user_habits:
            user_habits["corrections_log"] = []
        user_habits["corrections_log"].extend(hints["user_corrections"])
    
    # 4. 防火墙配置学习
    if mode == "firewall" and "firewall_config" in user_habits:
        fw = user_habits["firewall_config"]
        output = task_output
        # 如果用户手动添加了管理IP，记录下来
        if output.get("admin_ips_added"):
            fw["admin_ips"].extend(output["admin_ips_added"])
    
    user_habits["last_updated"] = datetime.now().isoformat()
    return user_habits
```

---

## 偏好注入（下次调用时）

当 Hermes agent 下次调用 skill 时，在 system prompt 中注入用户习惯：

```python
def build_skill_prompt(user_habits: dict, task: str, mode: str) -> str:
    """构建注入用户偏好的 prompt"""
    
    prefs = user_habits.get("tool_preferences", {}).get(mode, {})
    fw_config = user_habits.get("firewall_config", {})
    
    habit_context = f"""
## 用户习惯偏好（来自历史学习）
- 技能等级: {user_habits.get('user_profile', {}).get('skill_level', '未知')}
- 偏好工具: {', '.join(prefs) if isinstance(prefs, list) else str(prefs)}
- 防火墙方案: {user_habits.get('user_profile', {}).get('firewall_solution', 'nftables')}
- 管理端口: {fw_config.get('open_ports', [22222, 80, 443])}
- 历史成功工作流: {user_habits.get('workflow_history', [])[-3:]}  # 最近3条
- 已知用户纠正记录: {user_habits.get('corrections_log', [])[-5:]}  # 最近5条
"""
    return habit_context + "\n当前任务: " + task
```

---

## 多步骤任务链示例

**场景：从GitHub学习漏洞 → 沙盒复现 → 提取防御规则 → 更新防火墙**

```
Step 1: learn_from_github(["vulhub/vulhub"], extract_rules=True)
  → 产出: CVE详情, 攻击特征, 临时规则草稿

Step 2: sandbox_test(test_type="vuln_repro", target_image="vulhub/xxxx")
  → 产出: 复现确认, 网络流量特征, 防御验证

Step 3: update_firewall(action="add_rules", manual_rules=[从Step1提取的规则])
  → 产出: 规则添加确认, 防火墙状态

Step 4: [Hermes habit更新]
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