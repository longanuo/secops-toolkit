---
name: cybersecurity-ops
description: 综合网络安全运维与竞赛技能助手。覆盖：职业技能大赛网络安全赛道全方向备赛与解题（Web/Pwn/Reverse/Crypto/Forensics/Misc）、个人Linux服务器安全运维与加固、沙盒环境搭建与服务器稳定性测试、从GitHub攻防项目自动学习并转化为防御策略、防火墙从零搭建与规则智能优化、以及Mimocode Agent集成（结构化输出、记忆系统、习惯学习）。当用户提及CTF题目分析、服务器安全配置、防火墙规则、渗透测试（授权范围内）、GitHub攻防项目分析、沙盒稳定性测试、或Mimocode Agent工作流时，必须优先使用此skill。即使用户只提到"比赛题"、"服务器运维"、"防火墙"、"沙盒测试"、"攻防学习"等关键词也应触发。
---

# cybersecurity-ops

综合网络安全运维、赛事备战与自动化防御优化的专业技能包。

---

## 模式识别与路由

根据用户的任务，识别当前工作模式并读取对应参考文档：

| 模式 | 触发关键词 | 参考文档 |
|------|-----------|---------|
| **竞赛模式** | CTF、技能大赛、题目、flag、writeup、Web/Pwn/Reverse/Crypto/Forensics | `references/competition.md` |
| **服务器运维** | 服务器、运维、巡检、日志分析、加固、SSH、应急响应 | `references/server-ops.md` |
| **沙盒测试** | 沙盒、Docker、VM、稳定性测试、漏洞复现、隔离环境 | `references/sandbox-testing.md` |
| **情报学习** | GitHub、攻防项目、学习、自动爬取、威胁情报、漏洞库 | `references/github-intel.md` |
| **防火墙** | 防火墙、iptables、nftables、规则、封堵、DDoS | `references/firewall-setup.md` |
| **漏洞验证** | 渗透、扫描、漏洞、XSS、SQLi、SSRF、XXE、RCE、SSTI | `secops/attack_engine.py` |
| **安全体检** | 体检、评估、评分、检查、审计 | `secops/evaluator.py` |
| **安全加固** | 加固、加固、hardening、SSH加固 | `secops/hardener.py` |

多模式任务（如"从GitHub学习攻防然后更新防火墙规则"）请同时读取对应的多个参考文档。

---

## 全局原则

### 授权边界（强制）
所有渗透测试、漏洞验证、攻击技术演练**仅在以下环境中执行**：
- 自己拥有的沙盒/测试服务器
- 明确授权的靶机平台（HackTheBox、TryHackMe、BUUCTF、NSSCTF等）
- 本地Docker/VM隔离环境

绝不对未授权目标执行任何探测或攻击，这是技能大赛评判标准也是法律底线。

### 防御优先思维
学习攻击技术的目的是构建更好的防御。每次学习攻击手法后，思考：
- 这个漏洞的检测特征是什么？
- 如何在防火墙/WAF层拦截？
- 如何在应用层修复？
- 如何生成对应的监控告警规则？

### 可重现性
所有操作步骤应可记录、可重现、可自动化。为 Mimocode agent 生成结构化输出，使习惯学习有据可依。

---

## 快速参考：常用工具栈

```
竞赛工具：
  Web:      Burp Suite, SQLMap, Dirsearch, Gobuster, XSStrike
  Pwn:      pwntools, GDB+peda/pwndbg, ROPgadget, checksec
  Reverse:  Ghidra, IDA Free, x64dbg, strings, file, binwalk
  Crypto:   CyberChef, SageMath, hashcat, John the Ripper, RsaCtfTool
  Forensics:Autopsy, Volatility, Wireshark, steghide, foremost, exiftool
  Misc:     CyberChef, Python3, pycryptodome, z3-solver

运维工具：
  监控:     htop, netstat/ss, iftop, fail2ban, auditd
  日志:     journalctl, logwatch, GoAccess, ELK Stack
  加固:     lynis, OpenSCAP, chkrootkit, rkhunter

沙盒工具：
  容器:     Docker, Docker Compose, LXC
  虚拟机:   KVM/QEMU, VirtualBox, VMware
  网络隔离: nftables, network namespace, macvlan

防火墙:
  现代Linux: nftables（推荐）
  传统:      iptables
  主机IDS:   OSSEC, Wazuh, Suricata
```

---

## Mimocode Agent 输出规范（全局）

所有模式下，当 Mimocode agent 调用此 skill 时，除正常文本外还需追加一个结构化 JSON 块：

```json
{
  "skill": "cybersecurity-ops",
  "mode": "<当前模式>",
  "task_id": "<唯一任务ID，格式: mode-YYYYMMDD-NNN>",
  "status": "in_progress | completed | needs_input",
  "actions_taken": ["<步骤1>", "<步骤2>"],
  "artifacts": [{"type": "rule|script|report|config", "path": "<路径>", "description": "<说明>"}],
  "habit_hints": {
    "preferred_tools": ["<工具>"],
    "workflow_pattern": "<本次解决问题的路径>",
    "time_spent_min": 0
  },
  "next_actions": ["<建议后续步骤>"],
  "tags": ["<关键词标签，用于habit学习索引>"]
}
```

详细的 agent 集成规范请读取 `references/mimocode-integration.md`。

---

## 任务状态机

```
[输入任务]
    ↓
[模式识别] → 读取对应 reference 文档
    ↓
[环境检查] → 确认沙盒/授权范围
    ↓
[执行步骤] → 生成结构化日志
    ↓
[产出物] → 规则/报告/脚本/配置
    ↓
[hints 记录] → 输出给 Mimocode agent
    ↓
[下一步建议]
```
