"""从 GitHub 公开仓库拉取最新攻防 payload (使用 GitHub API)"""
import requests
import base64
import json
import os
import time

API_BASE = "https://api.github.com"

SOURCES = [
    ("swisskyrepo", "PayloadsAllTheThings", "XSS Injection/README.md", "XSS"),
    ("swisskyrepo", "PayloadsAllTheThings", "SQL Injection/README.md", "SQLi"),
    ("swisskyrepo", "PayloadsAllTheThings", "Server Side Template Injection/README.md", "SSTI"),
    ("swisskyrepo", "PayloadsAllTheThings", "Server Side Request Forgery/README.md", "SSRF"),
    ("swisskyrepo", "PayloadsAllTheThings", "XXE Injection/README.md", "XXE"),
    ("swisskyrepo", "PayloadsAllTheThings", "Command Injection/README.md", "RCE"),
    ("swisskyrepo", "PayloadsAllTheThings", "File Inclusion/README.md", "LFI"),
    ("swisskyrepo", "PayloadsAllTheThings", "NoSQL Injection/README.md", "NoSQLi"),
    ("swisskyrepo", "PayloadsAllTheThings", "LDAP Injection/README.md", "LDAP"),
    ("swisskyrepo", "PayloadsAllTheThings", "Insecure Deserialization/README.md", "Deserialization"),
    ("swisskyrepo", "PayloadsAllTheThings", "CRLF Injection/README.md", "CRLF"),
    ("swisskyrepo", "PayloadsAllTheThings", "HTTP Header Injection/README.md", "HeaderInjection"),
    ("danielmiessler", "SecLists", "Fuzzing/special-chars.txt", "FuzzChars"),
    ("danielmiessler", "SecLists", "Discovery/Web-Content/common.txt", "DirFuzz"),
]

HEADERS = {"User-Agent": "secops/3.0", "Accept": "application/vnd.github.v3+json"}


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
        if in_code and stripped and len(stripped) > 2 and not stripped.startswith("#"):
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
    print("  GitHub Payload Fetcher (API Mode)")
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
    for cat, pl in sorted(all_payloads.items()):
        print(f"    {cat}: {len(pl)}")

    output_dir = os.path.join(os.path.dirname(__file__), "..", "secops-offense", "secops_offense", "cache", "github_payloads")
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "latest_payloads.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_payloads, f, ensure_ascii=False, indent=2)
    print(f"\n  Saved: {output_file}")

    return all_payloads


if __name__ == "__main__":
    main()
