"""统一配置管理"""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent

CACHE_DIR = Path(os.environ.get("SECOPS_CACHE_DIR", os.path.expanduser("~/.secops/cache")))
LOG_DIR = Path(os.environ.get("SECOPS_LOG_DIR", os.path.expanduser("~/.secops/logs")))
REPORT_DIR = Path(os.environ.get("SECOPS_REPORT_DIR", str(PROJECT_ROOT / "reports")))

GITHUB_RAW_BASE = "https://raw.githubusercontent.com"
GITHUB_CACHE_TTL_HOURS = int(os.environ.get("SECOPS_CACHE_TTL", "24"))

HTTP_TIMEOUT = int(os.environ.get("SECOPS_HTTP_TIMEOUT", "8"))
HTTP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

INTEL_DIR_LINUX = "/opt/cybersec/intel/ips"
INTEL_DIR_WINDOWS = "C:\\Program Files\\SecOps"

WEBHOOK_URL = os.environ.get("SECOPS_WEBHOOK_URL", "")

HABITS_DIR = os.path.expanduser("~/.config/secops")
HABITS_FILE = os.path.join(HABITS_DIR, "user_habits.json")

ATTACK_DELAY = float(os.environ.get("SECOPS_ATTACK_DELAY", "0.15"))
ATTACK_TIME_BASED_DELAY = float(os.environ.get("SECOPS_TIME_DELAY", "5"))

# --- 新增配置 ---
# 代理池配置
PROXY_POOL_ENABLED = os.environ.get("SECOPS_PROXY_POOL_ENABLED", "true").lower() == "true"
PROXY_FILE_PATH = Path(os.environ.get("SECOPS_PROXY_FILE", str(CACHE_DIR / "proxies.txt")))

# 流量抖动配置
TRAFFIC_JITTER_ENABLED = os.environ.get("SECOPS_JITTER_ENABLED", "true").lower() == "true"
TRAFFIC_JITTER_BASE_DELAY = float(os.environ.get("SECOPS_JITTER_DELAY", "0.3"))
TRAFFIC_JITTER_FACTOR = float(os.environ.get("SECOPS_JITTER_FACTOR", "0.5"))

# Agent 状态机配置
AGENT_TIMEOUT = int(os.environ.get("SECOPS_AGENT_TIMEOUT", "300"))
AGENT_MAX_RETRIES = int(os.environ.get("SECOPS_AGENT_MAX_RETRIES", "3"))
CIRCUIT_BREAKER_THRESHOLD = int(os.environ.get("SECOPS_CIRCUIT_THRESHOLD", "5"))
CIRCUIT_RECOVERY_TIMEOUT = float(os.environ.get("SECOPS_CIRCUIT_RECOVERY", "60"))

# 日志同步配置
LOG_SYNC_ENABLED = os.environ.get("SECOPS_LOG_SYNC_ENABLED", "true").lower() == "true"
LOG_SYNC_MAX_ENTRIES = int(os.environ.get("SECOPS_LOG_SYNC_MAX", "1000"))
LOG_SYNC_MAX_CONTEXT_TOKENS = int(os.environ.get("SECOPS_LOG_SYNC_TOKENS", "8000"))


def ensure_dirs():
    for d in [CACHE_DIR, LOG_DIR, REPORT_DIR]:
        d.mkdir(parents=True, exist_ok=True)
