"""流量抖动调度器 — WAF 绕过与反指纹"""
import random
import time
import hashlib
from typing import Optional, Tuple
from secops_core.config import ATTACK_DELAY

# 常见浏览器指纹池
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

ACCEPT_LANGUAGES = [
    "zh-CN,zh;q=0.9,en;q=0.8",
    "en-US,en;q=0.9",
    "zh-CN,zh;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "ja,en-US;q=0.9,en;q=0.8",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.baidu.com/",
    "",  # 直接访问
]


class TrafficJitter:
    def __init__(self, base_delay: float = None):
        self.base_delay = base_delay or ATTACK_DELAY
        self._request_count = 0
        self._last_request_time = 0

    def calculate_delay(self, jitter_factor: float = 0.5) -> float:
        jitter = random.uniform(-jitter_factor, jitter_factor)
        delay = self.base_delay * (1 + jitter)
        if self._request_count > 0 and self._last_request_time > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.base_delay * 0.5:
                delay = max(delay, self.base_delay * 0.3)
        return max(0.05, delay)

    def wait(self, jitter_factor: float = 0.5):
        delay = self.calculate_delay(jitter_factor)
        time.sleep(delay)
        self._request_count += 1
        self._last_request_time = time.time()

    def get_random_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def get_random_headers(self, referer: bool = False) -> dict:
        headers = {
            "User-Agent": self.get_random_ua(),
            "Accept": random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if referer:
            ref = random.choice(REFERERS)
            if ref:
                headers["Referer"] = ref
        return headers

    def fingerprint_bypass_headers(self, target_domain: str) -> dict:
        ua = self.get_random_ua()
        ts = int(time.time())
        nonce = hashlib.md5(f"{target_domain}{ts}".encode()).hexdigest()[:8]
        return {
            "User-Agent": ua,
            "Accept": random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "X-Forwarded-For": self._random_ip(),
            "X-Real-IP": self._random_ip(),
            "Cache-Control": random.choice(["no-cache", "max-age=0"]),
            "Pragma": random.choice(["no-cache", "1"]),
            "Sec-Ch-Ua": self._build_ch_ua(ua),
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": self._extract_platform(ua),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": random.choice(["1", "0"]),
        }

    def _random_ip(self) -> str:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _build_ch_ua(self, ua: str) -> str:
        if "Chrome" in ua:
            version = ua.split("Chrome/")[1].split(" ")[0] if "Chrome/" in ua else "120.0.0.0"
            major = version.split(".")[0]
            return f'"Not_A Brand";v="8", "Chromium";v="{major}", "Google Chrome";v="{major}"'
        elif "Firefox" in ua:
            return '"Not_A Brand";v="8", "Chromium";v="120", "Firefox";v="121"'
        return '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'

    def _extract_platform(self, ua: str) -> str:
        if "Windows" in ua:
            return '"Windows"'
        elif "Mac" in ua:
            return '"macOS"'
        elif "Linux" in ua:
            return '"Linux"'
        return '"Windows"'

    def get_stats(self) -> dict:
        return {
            "request_count": self._request_count,
            "base_delay": self.base_delay,
        }


jitter = TrafficJitter()
