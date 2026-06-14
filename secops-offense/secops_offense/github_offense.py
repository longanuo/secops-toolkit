"""
GitHub 攻防仓库自动学习引擎
从 PayloadsAllTheThings / SecLists / payloadbox / nuclei-templates 等仓库
实时拉取最新攻击手法，动态扩充 arsenal 弹药库。

模块职责：
  1. 拉取 GitHub 仓库中的 payload 文件
  2. 解析、去重、分类、标注来源
  3. 缓存到本地避免重复请求
  4. 供 arsenal / online_scanner / fuzz_engine 消费
"""

import os
import re
import json
import time
import hashlib
import requests
from datetime import datetime, timedelta
from pathlib import Path

# ============================================================
#  配置区：仓库 -> 文件映射
# ============================================================

# 格式：(owner, repo, branch, remote_path, category, description)
PAYLOAD_SOURCES = [
    # ---- XSS ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "XSS Injection/README.md", "XSS",
     "PayloadsAllTheThings XSS 全集"),

    ("hakluke", "weaponised-XSS-payloads", "main",
     "README.md", "XSS",
     "hakluke weaponised XSS payloads (实战型)"),

    # ---- SQLi ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "SQL Injection/README.md", "SQLi",
     "PayloadsAllTheThings SQL注入全集"),

    ("trietptm", "SQL-Injection-Payloads", "master",
     "sqli-misc.txt", "SQLi",
     "trietptm SQL注入Payload合集 (BurpSuite)"),

    # ---- SSTI ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "Server Side Template Injection/README.md", "SSTI",
     "PayloadsAllTheThings SSTI 全集"),

    # ---- SSRF ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "Server Side Request Forgery/README.md", "SSRF",
     "PayloadsAllTheThings SSRF 全集"),

    # ---- LFI / Path Traversal ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "File Inclusion/README.md", "LFI",
     "PayloadsAllTheThings 文件包含全集"),

    # ---- XXE ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "XXE Injection/README.md", "XXE",
     "PayloadsAllTheThings XXE 全集"),

    # ---- OS Command Injection ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "Command Injection/README.md", "CMDi",
     "PayloadsAllTheThings 命令注入全集"),

    # ---- NoSQL Injection ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "NoSQL Injection/README.md", "NoSQLi",
     "PayloadsAllTheThings NoSQL注入全集"),

    # ---- LDAP Injection ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "LDAP Injection/README.md", "LDAP",
     "PayloadsAllTheThings LDAP注入全集"),

    # ---- CSV Injection ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "CSV Injection/README.md", "CSVi",
     "PayloadsAllTheThings CSV注入全集"),

    # ---- XPATH Injection ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "XPATH Injection/README.md", "XPATHi",
     "PayloadsAllTheThings XPATH注入全集"),

    # ---- Insecure Deserialization ----
    ("swisskyrepo", "PayloadsAllTheThings", "master",
     "Insecure Deserialization/README.md", "Deserialization",
     "PayloadsAllTheThings 反序列化攻击"),

    # ---- Fuzzing wordlists (SecLists) ----
    ("danielmiessler", "SecLists", "master",
     "Discovery/Web-Content/common.txt", "DirFuzz",
     "SecLists 常用目录字典"),

    ("danielmiessler", "SecLists", "master",
     "Fuzzing/special-chars.txt", "FuzzChars",
     "SecLists 特殊字符Fuzz字典"),

    # ---- SQLi (BurpSuite format) ----
    ("trietptm", "SQL-Injection-Payloads", "master",
     "sql-rmccurdy.com.txt", "SQLi",
     "rmccurdy SQL注入Payload大全"),
]

# GitHub raw 文件基础 URL
RAW_BASE = "https://raw.githubusercontent.com"

# 本地缓存目录
CACHE_DIR = Path(__file__).parent / "cache" / "github_payloads"
CACHE_META = CACHE_DIR / "_meta.json"

# 缓存有效期（小时）
CACHE_TTL_HOURS = 24


# ============================================================
#  缓存管理
# ============================================================

def _load_meta():
    if CACHE_META.exists():
        try:
            with open(CACHE_META, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_meta(meta):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with open(CACHE_META, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def _cache_key(owner, repo, branch, path):
    raw = f"{owner}/{repo}/{branch}/{path}"
    return hashlib.md5(raw.encode()).hexdigest()


def _is_cache_valid(cache_key, meta):
    entry = meta.get(cache_key)
    if not entry:
        return False
    cached_at = datetime.fromisoformat(entry.get("cached_at", "2000-01-01"))
    return datetime.now() - cached_at < timedelta(hours=CACHE_TTL_HOURS)


# ============================================================
#  GitHub 拉取核心
# ============================================================

def fetch_raw(owner, repo, branch, path, timeout=20):
    url = f"{RAW_BASE}/{owner}/{repo}/{branch}/{path}"
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "secops-offense-engine/1.0"
        })
        if resp.status_code == 200:
            return resp.text, None
        else:
            return None, f"HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        return None, "请求超时"
    except Exception as e:
        return None, str(e)


def fetch_with_cache(owner, repo, branch, path, category, description,
                     force_refresh=False):
    meta = _load_meta()
    key = _cache_key(owner, repo, branch, path)

    if not force_refresh and _is_cache_valid(key, meta):
        cache_file = CACHE_DIR / f"{key}.txt"
        if cache_file.exists():
            with open(cache_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
            return lines, True, None

    content, err = fetch_raw(owner, repo, branch, path)
    if err:
        return [], False, err

    lines = content.splitlines()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / f"{key}.txt"
    with open(cache_file, "w", encoding="utf-8") as f:
        f.write(content)

    meta[key] = {
        "owner": owner, "repo": repo, "branch": branch,
        "path": path, "category": category, "description": description,
        "cached_at": datetime.now().isoformat(),
        "line_count": len(lines),
        "url": f"{RAW_BASE}/{owner}/{repo}/{branch}/{path}"
    }
    _save_meta(meta)

    return lines, False, None


# ============================================================
#  Payload 解析器
# ============================================================

def _extract_payloads_from_markdown(content_lines, category):
    """从 PayloadsAllTheThings README.md 的代码块中提取 payload"""
    payloads = []
    in_code_block = False
    code_block_content = []

    for line in content_lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code_block:
                for cp in code_block_content:
                    cp = cp.strip()
                    if cp and len(cp) > 2 and not cp.startswith("#"):
                        payloads.append(cp)
                code_block_content = []
            in_code_block = not in_code_block
            continue
        if in_code_block:
            code_block_content.append(stripped)

    return payloads


def _extract_payloads_from_plaintext(content_lines, category):
    """从 payloadbox 纯文本格式提取（每行一个 payload）"""
    payloads = []
    for line in content_lines:
        line = line.strip()
        if line and not line.startswith("#") and len(line) > 2:
            payloads.append(line)
    return payloads


def _extract_fuzzing_wordlist(content_lines, category):
    """从 SecLists 字典文件提取"""
    entries = []
    for line in content_lines:
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("//"):
            entries.append(line)
    return entries


# ============================================================
#  主 API
# ============================================================

def learn_from_github(categories=None, force_refresh=False, verbose=True):
    """
    从 GitHub 仓库自动学习攻击 payload

    :param categories: 要学习的类别列表，None=全部
    :param force_refresh: 强制刷新缓存
    :param verbose: 打印详细日志
    :return: dict {category: [payload_list]}
    """
    if verbose:
        print("\n" + "=" * 60)
        print("  GitHub 攻防仓库自动学习引擎")
        print("=" * 60)
        print(f"  数据源: {len(PAYLOAD_SOURCES)} 个仓库/文件")
        print(f"  缓存目录: {CACHE_DIR}")
        print(f"  缓存有效期: {CACHE_TTL_HOURS} 小时")
        if categories:
            print(f"  目标类别: {', '.join(categories)}")
        print()

    result = {}
    stats = {"total": 0, "cached": 0, "fetched": 0, "errors": 0, "payloads": 0}

    for owner, repo, branch, path, category, description in PAYLOAD_SOURCES:
        if categories and category not in categories:
            continue

        if verbose:
            short_repo = f"{owner}/{repo}"
            print(f"  [{category}] {short_repo}/{path[:50]}...", end=" ")

        lines, from_cache, err = fetch_with_cache(
            owner, repo, branch, path, category, description, force_refresh
        )

        stats["total"] += 1

        if err:
            stats["errors"] += 1
            if verbose:
                print(f"X {err}")
            continue

        if from_cache:
            stats["cached"] += 1
        else:
            stats["fetched"] += 1
            if not force_refresh:
                time.sleep(0.5)

        if path.endswith(".md"):
            payloads = _extract_payloads_from_markdown(lines, category)
        elif "common.txt" in path or "api-endpoints" in path:
            payloads = _extract_fuzzing_wordlist(lines, category)
        else:
            payloads = _extract_payloads_from_plaintext(lines, category)

        if category not in result:
            result[category] = []
        result[category].extend(payloads)
        stats["payloads"] += len(payloads)

        if verbose:
            cache_tag = "cached" if from_cache else "online"
            print(f"OK {cache_tag} {len(payloads)} payloads")

    # 去重
    for cat in result:
        before = len(result[cat])
        result[cat] = list(dict.fromkeys(result[cat]))
        after = len(result[cat])
        if before != after:
            stats["payloads"] -= (before - after)

    if verbose:
        print(f"\n  Learning complete:")
        print(f"    Sources: {stats['total']} (cached {stats['cached']}, fetched {stats['fetched']})")
        print(f"    Errors: {stats['errors']}")
        print(f"    Total payloads: {stats['payloads']}")
        print(f"    Categories: {', '.join(sorted(result.keys()))}")

    return result


def get_arsenal_snapshot(categories=None):
    """获取当前弹药库快照（仅从缓存读取）"""
    meta = _load_meta()
    snapshot = {}
    for key, entry in meta.items():
        cat = entry.get("category", "unknown")
        if categories and cat not in categories:
            continue
        count = entry.get("line_count", 0)
        snapshot[cat] = snapshot.get(cat, 0) + count
    return snapshot


def list_sources():
    """列出所有配置的数据源"""
    print("\n  GitHub Offense Data Sources:")
    print(f"  {'Category':<15} {'Repository':<35} {'File Path'}")
    print(f"  {'-'*15} {'-'*35} {'-'*40}")
    for owner, repo, branch, path, category, desc in PAYLOAD_SOURCES:
        print(f"  {category:<15} {owner}/{repo:<33} {path[:50]}")


def merge_into_arsenal(learned_payloads, arsenal_module=None):
    """
    将学习到的 payload 合并到现有 arsenal.PAYLOADS
    """
    if arsenal_module is None:
        from secops_offense import arsenal
        arsenal_module = arsenal

    original = arsenal_module.PAYLOADS.copy()
    merge_stats = {}

    for category, payloads in learned_payloads.items():
        if not payloads:
            continue
        mapped_cat = _map_category(category)
        if mapped_cat is None:
            continue

        existing = set(original.get(mapped_cat, []))
        new_payloads = [p for p in payloads if p not in existing]
        if new_payloads:
            if mapped_cat not in original:
                original[mapped_cat] = []
            original[mapped_cat].extend(new_payloads)
            merge_stats[mapped_cat] = len(new_payloads)

    arsenal_module.PAYLOADS = original

    if merge_stats:
        print("\n  Merged into arsenal:")
        for cat, count in merge_stats.items():
            total = len(original.get(cat, []))
            print(f"    {cat}: +{count} new (total {total})")

    return original


def _map_category(raw_category):
    """将学习类别映射到 arsenal 标准类别，None=不合并"""
    mapping = {
        "XSS": "XSS",
        "SQLi": "SQLi",
        "SSRF": "SSRF",
        "RCE": "RCE",
        "CMDi": "RCE",
        "SSTI": "SSTI",
        "LFI": "LFI",
        "XXE": "XXE",
        "NoSQLi": "NoSQLi",
        "LDAP": "LDAP",
        "CSVi": "CSVi",
        "XPATHi": "XPATHi",
        "JWT": "JWT",
        "Deserialization": "Deserialization",
        "HeaderInjection": "CRLF",
        "DirFuzz": "DirFuzz",
        "FuzzChars": "FuzzChars",
    }
    return mapping.get(raw_category)


# ============================================================
#  CLI 入口
# ============================================================

def run_offense_learning(categories=None, force=False):
    """完整学习流程：拉取 -> 解析 -> 合并 -> 统计"""
    learned = learn_from_github(categories=categories, force_refresh=force)

    if not learned:
        print("\n  [!] No payloads learned. Check network connection.")
        return

    merged = merge_into_arsenal(learned)

    print("\n  Arsenal Overview:")
    for cat, payloads in sorted(merged.items()):
        print(f"    {cat:<20} {len(payloads):>5} payloads")

    return merged


if __name__ == "__main__":
    import sys
    cats = sys.argv[1:] if len(sys.argv) > 1 else None
    run_offense_learning(categories=cats or None, force="--force" in sys.argv)
