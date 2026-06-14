"""
robots.txt 情报解析器

功能:
  1. 抓取 robots.txt，提取 Disallow 路径（隐藏路径 = 攻击面）
  2. 提取 Sitemap 中的关联站点（同一开发者 = 更多目标）
  3. 提取 Crawl-delay（判断是否有反爬策略）
  4. 自动对发现的隐藏路径发起探测
  5. 对关联站点做交叉分析
"""

import re
import urllib.parse
from typing import List, Dict, Tuple
from secops_core.logger import get_logger
from secops_core.http_client import http_get

log = get_logger("robots_parser")


def parse_robots_txt(target_url: str) -> Dict:
    """
    解析目标的 robots.txt，返回结构化情报
    
    返回:
    {
        "hidden_paths": ["/admin/", "/api/", ...],      # Disallow 路径
        "sitemaps": ["https://...sitemap.xml", ...],    # Sitemap URL
        "related_domains": ["pingzishuo.com", ...],     # 关联站点
        "crawl_delays": {"*": 1, "Baiduspider": 1},    # 爬虫延迟
        "user_agents": ["*", "Baiduspider", ...],       # 所有 UA
        "raw_content": "...",                            # 原始内容
    }
    """
    parsed = urllib.parse.urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = f"{base}/robots.txt"

    log.info(f"正在抓取 {robots_url}")
    status, headers, body = http_get(robots_url, timeout=8)

    if status != 200 or not body:
        log.info(f"robots.txt 不存在或不可访问 (HTTP {status})")
        return {"hidden_paths": [], "sitemaps": [], "related_domains": [],
                "crawl_delays": {}, "user_agents": [], "raw_content": ""}

    result = {
        "hidden_paths": [],
        "sitemaps": [],
        "related_domains": [],
        "crawl_delays": {},
        "user_agents": [],
        "raw_content": body,
        "robots_url": robots_url,
    }

    current_ua = "*"
    seen_paths = set()
    seen_domains = set()

    for line in body.splitlines():
        line = line.strip()

        # 跳过空行和注释
        if not line or line.startswith("#"):
            continue

        # 解析 User-agent
        if line.lower().startswith("user-agent:"):
            ua = line.split(":", 1)[1].strip()
            current_ua = ua
            if ua not in result["user_agents"]:
                result["user_agents"].append(ua)

        # 解析 Disallow（隐藏路径 = 攻击面）
        elif line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path not in seen_paths:
                seen_paths.add(path)
                result["hidden_paths"].append(path)

        # 解析 Allow（也可能暴露有趣路径）
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and path not in seen_paths:
                seen_paths.add(path)
                result["hidden_paths"].append(path)

        # 解析 Sitemap（关联站点 = 扩大攻击面）
        elif line.lower().startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            if sitemap_url:
                result["sitemaps"].append(sitemap_url)
                # 提取域名
                sitemap_parsed = urllib.parse.urlparse(sitemap_url)
                sitemap_domain = sitemap_parsed.netloc
                target_domain = parsed.netloc
                if sitemap_domain and sitemap_domain != target_domain and sitemap_domain not in seen_domains:
                    seen_domains.add(sitemap_domain)
                    result["related_domains"].append(sitemap_domain)

        # 解析 Crawl-delay
        elif line.lower().startswith("crawl-delay:"):
            try:
                delay = float(line.split(":", 1)[1].strip())
                result["crawl_delays"][current_ua] = delay
            except ValueError:
                pass

    log.info(f"发现 {len(result['hidden_paths'])} 个隐藏路径, "
             f"{len(result['sitemaps'])} 个 Sitemap, "
             f"{len(result['related_domains'])} 个关联站点")

    return result


def probe_hidden_paths(base_url: str, paths: list) -> List[Dict]:
    """
    对 robots.txt 中发现的隐藏路径进行探测
    返回可访问的路径列表（带状态码和大小）
    """
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    accessible = []
    for path in paths:
        # 跳过前端路由（#/xxx 是 SPA 路由，不是真实路径）
        if path.startswith("/#"):
            continue

        url = base + path
        try:
            status, headers, body = http_get(url, timeout=5)
            if status == 200 and body:
                accessible.append({
                    "path": path,
                    "url": url,
                    "status": status,
                    "size": len(body),
                    "has_content": len(body) > 100,
                })
                log.info(f"  [+] 可访问: {path} ({len(body)} bytes)")
            elif status in (301, 302, 307, 308):
                location = headers.get("location", "unknown")
                accessible.append({
                    "path": path,
                    "url": url,
                    "status": status,
                    "redirect_to": location,
                    "size": 0,
                })
                log.info(f"  [→] 重定向: {path} -> {location}")
        except Exception:
            pass

    return accessible


def analyze_sitemaps(sitemap_urls: list) -> List[Dict]:
    """
    抓取 Sitemap，提取所有子页面 URL
    """
    all_urls = []
    for sitemap_url in sitemap_urls:
        try:
            status, headers, body = http_get(sitemap_url, timeout=8)
            if status == 200 and body:
                # 提取 <loc> 标签中的 URL
                urls = re.findall(r"<loc>(.*?)</loc>", body, re.IGNORECASE)
                for url in urls:
                    all_urls.append({"url": url, "source": sitemap_url})
                log.info(f"  Sitemap {sitemap_url}: {len(urls)} 个 URL")
        except Exception:
            pass
    return all_urls


def scan_related_domains(related_domains: list) -> List[Dict]:
    """
    对关联站点做基础信息收集
    """
    results = []
    for domain in related_domains:
        url = f"https://{domain}"
        try:
            status, headers, body = http_get(url, timeout=5)
            if status == 200:
                # 提取标题
                title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
                title = title_match.group(1) if title_match else "N/A"
                results.append({
                    "domain": domain,
                    "url": url,
                    "status": status,
                    "title": title,
                    "size": len(body),
                })
                log.info(f"  关联站 {domain}: {title[:50]}")
        except Exception:
            pass
    return results


def generate_robots_report(robots_data: Dict, accessible_paths: list,
                           sitemap_urls: list, related_sites: list) -> str:
    """生成 robots.txt 情报报告"""
    lines = []
    lines.append("=" * 60)
    lines.append("  robots.txt 情报分析报告")
    lines.append("=" * 60)

    # 隐藏路径
    lines.append(f"\n  隐藏路径 ({len(robots_data['hidden_paths'])} 个):")
    for path in robots_data["hidden_paths"]:
        if path.startswith("/#"):
            lines.append(f"    [SPA]  {path}")
        else:
            lines.append(f"    [PATH] {path}")

    # 可访问路径
    if accessible_paths:
        lines.append(f"\n  可访问路径 ({len(accessible_paths)} 个):")
        for p in accessible_paths:
            if "redirect_to" in p:
                lines.append(f"    [→] {p['path']} -> {p['redirect_to']}")
            else:
                lines.append(f"    [✓] {p['path']}  HTTP {p['status']}  {p['size']} bytes")

    # 关联站点
    if related_sites:
        lines.append(f"\n  关联站点 ({len(related_sites)} 个):")
        for site in related_sites:
            lines.append(f"    [🌐] {site['domain']} - {site.get('title', 'N/A')[:50]}")

    # Sitemap
    if sitemap_urls:
        lines.append(f"\n  Sitemap 页面 ({len(sitemap_urls)} 个):")
        for u in sitemap_urls[:20]:
            lines.append(f"    [📄] {u['url'][:80]}")

    # 爬虫策略
    if robots_data["crawl_delays"]:
        lines.append(f"\n  爬虫延迟策略:")
        for ua, delay in robots_data["crawl_delays"].items():
            lines.append(f"    {ua}: {delay}s")

    return "\n".join(lines)
