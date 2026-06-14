# SRC 全流程提示词库

> **适用范围**：仅限已在 SRC 平台登记、授权范围内的目标  
> **版本**：v1.0 | 维护路径：`secops/src/prompts/`

---

## 目录

| 编号 | 名称 | 阶段 | 类型 |
|------|------|------|------|
| P-00 | 主系统提示词（SRC 模式） | 全局 | Claude 对话 |
| P-01 | JS 静态分析 | 被动侦查 | Claude 对话 |
| P-02 | Source Map 分析 | 被动侦查 | Claude 对话 |
| P-03 | 关联资产优先级分析 | 被动侦查 | Claude 对话 |
| P-04 | 敏感凭证影响评估 | 漏洞验证 | Claude 对话 |
| P-05 | Cookie & 会话安全审计 | 漏洞验证 | Claude 对话 |
| P-06 | API 攻击面 & 测试用例设计 | 漏洞验证 | Claude 对话 |
| P-07 | SRC 漏洞报告生成 | 报告撰写 | Claude 对话 |
| P-08 | CVSS 3.1 评分助手 | 报告撰写 | Claude 对话 |
| H-00 | Hermes SRC 模式 System Prompt | 全局 | Hermes Agent |
| H-01 | src_recon_skill.yaml | 被动侦查 | Hermes Agent |
| H-02 | JSON 输出规范 | 全局 | Hermes Agent |
| H-03 | hermes_bridge.py 集成片段 | 全局 | Hermes Agent |

---

## 文件结构

```
secops/src/
├── __init__.py                          # 模块初始化
├── README.md                            # 本文档
└── prompts/
    ├── p00_main_system.txt              # P-00 主系统提示词
    ├── p01_js_analysis.txt              # P-01 JS 静态分析
    ├── p02_sourcemap.txt                # P-02 Source Map 分析
    ├── p03_assets.txt                   # P-03 关联资产优先级
    ├── p04_credentials.txt              # P-04 敏感凭证评估
    ├── p05_cookie.txt                   # P-05 Cookie 审计
    ├── p06_api.txt                      # P-06 API 攻击面
    ├── p07_report.txt                   # P-07 漏洞报告生成
    ├── p08_cvss.txt                     # P-08 CVSS 评分
    ├── hermes_src_system.txt            # H-00 Hermes 系统提示词
    ├── src_output_schema.json           # H-02 JSON 输出规范
    └── hermes_bridge_src_integration.py # H-03 集成代码

secops/hermes_skill/
└── src_recon_skill.yaml                 # H-01 技能定义
```

---

## 快速参考：提示词选择决策树

```
开始挖洞
  ↓
拿到目标域名
  ├─ 抓 JS 文件  ──────────────→ P-01 JS静态分析
  ├─ 发现 .map 文件 ───────────→ P-02 Source Map分析
  ├─ 做子域名枚举 ─────────────→ P-03 关联资产优先级
  │
  └─ 发现线索（授权主动测试）
       ├─ 发现 Token/Secret ────→ P-04 凭证影响评估
       ├─ 抓到 HTTP 响应头 ─────→ P-05 Cookie审计
       ├─ 拿到 API 端点列表 ────→ P-06 API攻击面设计
       │
       └─ 验证完漏洞
            ├─ 写单条报告 ───────→ P-07 漏洞报告生成
            └─ 不确定严重程度 ───→ P-08 CVSS评分助手
```

---

## 使用方式

### Claude 对话版
1. 将 P-00 作为 Project 的 System Prompt 或第一条消息
2. 根据阶段选择对应提示词模板
3. 将变量（如 `{{target_domain}}`、`{{js_content}}`）替换为实际内容

### Hermes Agent 集成版
1. 确保 `src_recon_skill.yaml` 在 `secops/hermes_skill/` 目录
2. 将 `hermes_bridge_src_integration.py` 中的代码合并到 `hermes_bridge.py`
3. 通过 `run_src_task()` 函数调用对应阶段的任务

---

## 授权边界（强制）

- 所有操作仅限 SRC 平台登记的授权目标
- 被动侦查（JS分析、DNS、证书透明度）无需每次确认
- 主动探测（API测试、凭证验证）需设置 `active_testing: true`
- 绝不提供针对未授权目标的攻击性建议
