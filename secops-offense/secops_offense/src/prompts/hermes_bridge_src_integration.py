import json
import os
from datetime import datetime
from pathlib import Path

PROMPT_DIR = Path(__file__).parent / "src" / "prompts"
SCHEMA_PATH = Path(__file__).parent / "src" / "prompts" / "src_output_schema.json"

STAGE_PROMPT_MAP = {
    "passive_recon": {
        "js_analysis":        "p01_js_analysis.txt",
        "sourcemap_check":    "p02_sourcemap.txt",
        "asset_prioritization": "p03_assets.txt",
    },
    "vulnerability_validation": {
        "credential_assessment": "p04_credentials.txt",
        "cookie_audit":          "p05_cookie.txt",
        "api_attack_surface":    "p06_api.txt",
    },
    "report_generation": {
        "vuln_report":   "p07_report.txt",
        "cvss_scoring":  "p08_cvss.txt",
    },
}

def build_src_prompt(stage: str, task_id: str, input_data: dict) -> str:
    """
    加载对应阶段的提示词模板，注入输入数据，返回完整 prompt。
    """
    prompt_file = STAGE_PROMPT_MAP.get(stage, {}).get(task_id)
    if not prompt_file:
        raise ValueError(f"Unknown stage/task: {stage}/{task_id}")

    template_path = PROMPT_DIR / prompt_file
    if not template_path.exists():
        raise FileNotFoundError(f"Prompt template not found: {template_path}")

    template = template_path.read_text(encoding="utf-8")
    for key, value in input_data.items():
        placeholder = "{{" + key + "}}"
        if isinstance(value, list):
            value = "\n".join(str(v) for v in value)
        template = template.replace(placeholder, str(value))

    return template


def run_src_task(
    stage: str,
    task_id: str,
    input_data: dict,
    hermes_client,          # 你现有的 Hermes client 实例
    authorized_targets: list[str],
    active_testing: bool = False,
) -> dict:
    """
    执行单个 SRC 任务，返回结构化 JSON 输出。
    """
    # 授权检查
    target = input_data.get("target_domain", "")
    if target and not any(target.endswith(t) for t in authorized_targets):
        return {
            "status": "out_of_scope",
            "error": f"Target {target} not in authorized list: {authorized_targets}",
            "task_id": f"src-{datetime.now().strftime('%Y%m%d')}-err",
        }

    # 主动测试阶段需要额外确认
    if stage == "vulnerability_validation" and not active_testing:
        return {
            "status": "needs_active_testing",
            "error": "Set active_testing=True to run vulnerability validation tasks.",
            "task_id": f"src-{datetime.now().strftime('%Y%m%d')}-pending",
        }

    # 加载 system prompt
    system_prompt_path = PROMPT_DIR / "hermes_src_system.txt"
    system_prompt = system_prompt_path.read_text(encoding="utf-8") if system_prompt_path.exists() else ""

    # 构建用户 prompt
    user_prompt = build_src_prompt(stage, task_id, input_data)

    # 调用 Hermes（使用你现有的接口）
    raw_response = hermes_client.chat(
        system=system_prompt,
        user=user_prompt,
        response_format="json",   # Hermes structured output mode
    )

    # 解析并补全元数据
    try:
        result = json.loads(raw_response) if isinstance(raw_response, str) else raw_response
    except json.JSONDecodeError:
        result = {"raw": raw_response, "parse_error": True}

    result.setdefault("task_id", f"src-{datetime.now().strftime('%Y%m%d')}-{task_id[:3].upper()}")
    result.setdefault("stage", stage)
    result.setdefault("timestamp", datetime.now().isoformat())

    # 自动保存输出
    output_path = Path("reports") / f"{result['task_id']}.json"
    output_path.parent.mkdir(exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    return result


# ── 调用示例 ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 示例：对 JS 内容进行静态分析
    from secops.hermes_bridge import HermesClient  # 替换为你实际的 client

    client = HermesClient()

    result = run_src_task(
        stage="passive_recon",
        task_id="js_analysis",
        input_data={
            "target_domain": "shushubuyue.com",
            "js_content": open("target_app.js").read(),
        },
        hermes_client=client,
        authorized_targets=["shushubuyue.com", "unclenoway.net"],
        active_testing=False,
    )

    print(json.dumps(result, ensure_ascii=False, indent=2))
