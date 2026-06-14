"""统一 GitHub 内容拉取客户端"""
import json
import hashlib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from secops_core.config import GITHUB_RAW_BASE, CACHE_DIR, GITHUB_CACHE_TTL_HOURS
from secops_core.logger import get_logger

log = get_logger("github_client")

PAYLOAD_CACHE_DIR = CACHE_DIR / "github_payloads"
PAYLOAD_CACHE_META = PAYLOAD_CACHE_DIR / "_meta.json"


def _load_meta():
    if PAYLOAD_CACHE_META.exists():
        try:
            with open(PAYLOAD_CACHE_META, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_meta(meta):
    PAYLOAD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(PAYLOAD_CACHE_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def _cache_key(owner, repo, branch, path):
    return hashlib.md5(f"{owner}/{repo}/{branch}/{path}".encode()).hexdigest()


def _is_cache_valid(cache_key, meta):
    entry = meta.get(cache_key)
    if not entry:
        return False
    cached_at = datetime.fromisoformat(entry.get("cached_at", "2000-01-01"))
    return datetime.now() - cached_at < timedelta(hours=GITHUB_CACHE_TTL_HOURS)


def fetch_raw(owner, repo, branch, path, timeout=20):
    url = f"{GITHUB_RAW_BASE}/{owner}/{repo}/{branch}/{path}"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "secops-toolbox/2.0"})
        if resp.status_code == 200:
            return resp.text, None
        return None, f"HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        return None, "请求超时"
    except Exception as e:
        return None, str(e)


def fetch_with_cache(owner, repo, branch, path, category="", description="", force_refresh=False):
    meta = _load_meta()
    key = _cache_key(owner, repo, branch, path)
    if not force_refresh and _is_cache_valid(key, meta):
        cache_file = PAYLOAD_CACHE_DIR / f"{key}.txt"
        if cache_file.exists():
            with open(cache_file, "r", encoding="utf-8", errors="replace") as f:
                return f.read().splitlines(), True, None

    content, err = fetch_raw(owner, repo, branch, path)
    if err:
        return [], False, err

    lines = content.splitlines()
    PAYLOAD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(PAYLOAD_CACHE_DIR / f"{key}.txt", "w", encoding="utf-8") as f:
        f.write(content)

    meta[key] = {
        "owner": owner, "repo": repo, "branch": branch, "path": path,
        "category": category, "description": description,
        "cached_at": datetime.now().isoformat(), "line_count": len(lines),
        "url": f"{GITHUB_RAW_BASE}/{owner}/{repo}/{branch}/{path}"
    }
    _save_meta(meta)
    return lines, False, None


def get_cache_snapshot(categories=None):
    meta = _load_meta()
    snapshot = {}
    for key, entry in meta.items():
        cat = entry.get("category", "unknown")
        if categories and cat not in categories:
            continue
        snapshot[cat] = snapshot.get(cat, 0) + entry.get("line_count", 0)
    return snapshot
