"""从更多 GitHub 源拉取 payload"""
import requests
import base64
import json
import os
import time

API_BASE = "https://api.github.com"
HEADERS = {"User-Agent": "secops/3.0", "Accept": "application/vnd.github.v3+json"}

SOURCES = [
    # PayloadsAllTheThings 子目录
    ("swisskyrepo", "PayloadsAllTheThings", "Insecure Deserialization/README.md", "Deserialization"),
    ("swisskyrepo", "PayloadsAllTheThings", "Insecure Deserialization/Java.md", "Deserialization_Java"),
    ("swisskyrepo", "PayloadsAllTheThings", "Insecure Deserialization/PHP.md", "Deserialization_PHP"),
    ("swisskyrepo", "PayloadsAllTheThings", "Insecure Deserialization/Python.md", "Deserialization_Python"),
    # JWT 攻击
    ("swisskyrepo", "JWT_Tool", "README.md", "JWT"),
    # SSRF 绕过
    ("cujanovic", "SSRF-testing-wordslist", "ssrf_testing.txt", "SSRF"),
    # 目录扫描
    ("danielmiessler", "SecLists", "Discovery/Web-Content/api-endpoints.txt", "API_DirFuzz"),
    ("danielmiessler", "SecLists", "Discovery/Web-Content/directory-list-2.3-small.txt", "DirFuzz_Large"),
    # GraphQL
    ("doyensec", "intruder", "wordlists/graphql.txt", "GraphQL"),
    # WAF 绕过
    ("0xInfection", "AWAFBypass", "payloads/xss.txt", "WAF_Bypass_XSS"),
]


def fetch_file(owner, repo, path):
    url = f"{API_BASE}/repos/{owner}/{repo}/contents/{path}"
    try:
        resp = requests.get(url, timeout=15, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return content, None
        return None, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, str(e)


def extract_from_markdown(text):
    payloads = []
    in_code = False
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code and stripped and len(stripped) > 2:
            payloads.append(stripped)
    return payloads


def extract_plaintext(text):
    payloads = []
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("//") and len(line) > 2:
            payloads.append(line)
    return payloads


def main():
    all_payloads = {}
    stats = {"ok": 0, "fail": 0, "total": 0}

    print("=" * 60)
    print("  GitHub Additional Sources Fetcher")
    print("=" * 60)

    for owner, repo, path, category in SOURCES:
        short = f"{owner}/{repo}"
        print(f"  [{category}] {short}/{path[:40]}...", end=" ", flush=True)

        content, err = fetch_file(owner, repo, path)
        if err:
            stats["fail"] += 1
            print(f"FAIL ({err})")
            time.sleep(1)
            continue

        if path.endswith(".md"):
            payloads = extract_from_markdown(content)
        else:
            payloads = extract_plaintext(content)

        stats["ok"] += 1
        stats["total"] += len(payloads)

        if category not in all_payloads:
            all_payloads[category] = []
        all_payloads[category].extend(payloads)
        all_payloads[category] = list(dict.fromkeys(all_payloads[category]))

        print(f"OK ({len(payloads)})")
        time.sleep(1)

    print(f"\n  Result: {stats['ok']}/{stats['ok']+stats['fail']} sources, {stats['total']} payloads")

    # 加载之前的 payload 并合并
    cache_file = os.path.join(os.path.dirname(__file__), "..", "secops-offense", "secops_offense", "cache", "github_payloads", "latest_payloads.json")
    existing = {}
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            existing = json.load(f)

    for cat, pl in all_payloads.items():
        if cat not in existing:
            existing[cat] = []
        existing[cat].extend(pl)
        existing[cat] = list(dict.fromkeys(existing[cat]))

    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

    print(f"\n  Merged totals:")
    for cat, pl in sorted(existing.items()):
        print(f"    {cat}: {len(pl)}")
    print(f"\n  Saved: {cache_file}")


if __name__ == "__main__":
    main()
