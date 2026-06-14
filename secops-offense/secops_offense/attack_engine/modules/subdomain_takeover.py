"""子域名接管检测器"""
from typing import List
from secops_core.http_client import http_get
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector
import time
import re


class SubdomainTakeoverDetector(BaseDetector):
    name = "subdomain_takeover"
    category = "Subdomain Takeover"

    VULNERABLE_SERVICES = {
        "s3.amazonaws.com": {"service": "AWS S3", "fingerprint": "NoSuchBucket"},
        "s3-website": {"service": "AWS S3", "fingerprint": "NoSuchBucket"},
        "amazonaws.com": {"service": "AWS", "fingerprint": "NoSuchBucket"},
        "herokuapp.com": {"service": "Heroku", "fingerprint": "No such app"},
        "herokussl.com": {"service": "Heroku", "fingerprint": "No such app"},
        "ghost.io": {"service": "Ghost", "fingerprint": "The thing you were looking for is no here"},
        "github.io": {"service": "GitHub Pages", "fingerprint": "There isn't a GitHub Pages site here"},
        "bitbucket.io": {"service": "Bitbucket", "fingerprint": "Repository not found"},
        "tumblr.com": {"service": "Tumblr", "fingerprint": "Whatever you were looking for"},
        "wordpress.com": {"service": "WordPress", "fingerprint": "Do you want to register"},
        "feedpress.me": {"service": "FeedPress", "fingerprint": "The feed has not been found"},
        "helpjuice.com": {"service": "HelpScout", "fingerprint": "We could not find what you're looking for"},
        "helpscoutdocs.com": {"service": "HelpScout", "fingerprint": "No settings were found"},
        "cargocollective.com": {"service": "Cargo", "fingerprint": "If you're moving your domain"},
        "statuspage.io": {"service": "Atlassian StatusPage", "fingerprint": "Better StatusPage"},
        "uservoice.com": {"service": "UserVoice", "fingerprint": "This UserVoice subdomain"},
        "surge.sh": {"service": "Surge.sh", "fingerprint": "project not found"},
        "intercom.help": {"service": "Intercom", "fingerprint": "This page is reserved for artistic dogs"},
        "webflow.io": {"service": "Webflow", "fingerprint": "The page you are looking for is not found"},
        "cloudfront.net": {"service": "AWS CloudFront", "fingerprint": "Bad Request"},
        "azurewebsites.net": {"service": "Azure", "fingerprint": "404 Web Site not found"},
        "trafficmanager.net": {"service": "Azure", "fingerprint": "404 Web Site not found"},
        "blob.core.windows.net": {"service": "Azure", "fingerprint": "404 The specified container does not exist"},
        "azure-api.net": {"service": "Azure", "fingerprint": "404 not found"},
        "azurehdinsight.net": {"service": "Azure", "fingerprint": "404 Not Found"},
        "azureedge.net": {"service": "Azure", "fingerprint": "404 Not Found"},
        "azurecontainers.io": {"service": "Azure", "fingerprint": "404 Not Found"},
        "database.windows.net": {"service": "Azure", "fingerprint": "404 not found"},
        "azuredatalakestore.net": {"service": "Azure", "fingerprint": "404 not found"},
        "search.windows.net": {"service": "Azure", "fingerprint": "404 not found"},
        "azurecr.io": {"service": "Azure", "fingerprint": "404 not found"},
        "redis.cache.windows.net": {"service": "Azure", "fingerprint": "404 not found"},
        "azurehdinsight.net": {"service": "Azure", "fingerprint": "404 Not Found"},
        "servicebus.windows.net": {"service": "Azure", "fingerprint": "404 not found"},
        "visualstudio.com": {"service": "Azure DevOps", "fingerprint": "404 page not found"},
        "squarespace.com": {"service": "Squarespace", "fingerprint": "No Such Account"},
        "strikingly.com": {"service": "Strikingly", "fingerprint": "But if you're looking for a website"},
        "landingi.com": {"service": "Landingi", "fingerprint": "It looks like you're lost"},
        "fastly.net": {"service": "Fastly", "fingerprint": "Fastly error: unknown domain"},
        "pantheon.io": {"service": "Pantheon", "fingerprint": "404 error unknown site"},
        "teamwork.com": {"service": "Teamwork", "fingerprint": "Oops - We didn't find your site"},
        "helpjuice.com": {"service": "HelpJuice", "fingerprint": "We could not find what you're looking for"},
        "helpscoutdocs.com": {"service": "HelpScout", "fingerprint": "No settings were found"},
        "ngrok.io": {"service": "ngrok", "fingerprint": "Tunnel *.ngrok.io not found"},
        "ngrok-free.app": {"service": "ngrok", "fingerprint": "Tunnel *.ngrok-free.app not found"},
    }

    def test(self, target_url: str, subdomains: list = None, **kwargs) -> List[Finding]:
        findings = []
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        base_domain = parsed.netloc

        if not subdomains:
            subdomains = self._generate_common_subdomains(base_domain)

        for subdomain in subdomains:
            full_url = f"http://{subdomain}"
            log_audit("SUBDOMAIN_TAKEOVER", full_url, f"checking {subdomain}")

            status, headers, body = http_get(full_url, timeout=5)

            if status == 0:
                time.sleep(ATTACK_DELAY)
                continue

            for cname_suffix, service_info in self.VULNERABLE_SERVICES.items():
                if cname_suffix in headers.get("Server", "").lower() or \
                   cname_suffix in body.lower() or \
                   cname_suffix in headers.get("X-Powered-By", "").lower():

                    fingerprint = service_info["fingerprint"]
                    if fingerprint.lower() in body.lower():
                        findings.append(Finding(
                            vuln_type="Subdomain Takeover", severity="critical",
                            title=f"子域名接管风险 - {subdomain}",
                            location=full_url, payload=f"CNAME -> {cname_suffix}",
                            evidence=f"服务: {service_info['service']}, 指纹: {fingerprint[:80]}",
                            description=f"子域名 {subdomain} 指向 {service_info['service']} 但内容未配置，"
                                       f"攻击者可接管该子域名。",
                            remediation=f"删除或重新配置 {subdomain} 的 DNS CNAME 记录"
                        ))
                        break

            cname_body = body
            if "CNAME" in body or "cname" in body:
                cnames = re.findall(r'([a-zA-Z0-9._-]+\.(com|io|net|org))', cname_body)
                for cname in cnames:
                    cname_domain = cname[0]
                    try:
                        status2, _, body2 = http_get(f"http://{cname_domain}", timeout=3)
                        if status2 == 0:
                            findings.append(Finding(
                                vuln_type="Subdomain Takeover", severity="high",
                                title=f"疑似子域名接管 - {subdomain}",
                                location=full_url, payload=f"CNAME -> {cname_domain}",
                                evidence=f"CNAME 目标 {cname_domain} 无法访问",
                                description=f"子域名 {subdomain} 的 CNAME 目标 {cname_domain} 无响应。",
                                remediation=f"验证 {cname_domain} 的所有权并重新配置 DNS"
                            ))
                    except Exception:
                        pass

            time.sleep(ATTACK_DELAY)

        return findings

    def _generate_common_subdomains(self, domain: str) -> list:
        parts = domain.split(".")
        base = ".".join(parts[:-1]) if len(parts) > 1 else domain
        prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2",
            "dns", "mx", "vpn", "api", "dev", "staging", "test", "admin",
            "portal", "app", "web", "blog", "shop", "store", "cdn",
            "static", "media", "assets", "img", "images", "docs",
            "support", "help", "status", "monitor", "grafana", "kibana",
            "jenkins", "gitlab", "git", "repo", "ci", "cd", "drone",
            "k8s", "docker", "registry", "db", "mysql", "postgres",
            "redis", "mongo", "es", "elastic", "rabbit", "mq",
            "old", "new", "beta", "alpha", "demo", "sandbox", "stage",
            "qa", "uat", "pre", "preprod", "canary", "edge",
            "backup", "bak", "temp", "tmp", "archive", "legacy",
        ]
        return [f"{p}.{domain}" for p in prefixes]
