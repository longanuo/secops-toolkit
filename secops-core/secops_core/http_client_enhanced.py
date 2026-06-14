"""增强型 HTTP 客户端 — 集成代理池与流量抖动"""
import time
import requests
import urllib3
from typing import Optional, Tuple, Dict
from secops_core.config import HTTP_TIMEOUT, HTTP_USER_AGENT
from secops_core.proxy_pool import pool as proxy_pool
from secops_core.traffic_jitter import jitter
from secops_core.logger import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = get_logger("http_client")

DEFAULT_HEADERS = {"User-Agent": HTTP_USER_AGENT}


class HTTPClient:
    def __init__(self, use_proxy: bool = True, use_jitter: bool = True,
                 max_retries: int = 3, timeout: int = None):
        self.use_proxy = use_proxy
        self.use_jitter = use_jitter
        self.max_retries = max_retries
        self.timeout = timeout or HTTP_TIMEOUT
        self._session = requests.Session()
        self._request_count = 0
        self._error_count = 0

    def get(self, url: str, headers: dict = None, timeout: int = None, **kwargs) -> Tuple[int, dict, str]:
        return self._request("GET", url, headers=headers, timeout=timeout, **kwargs)

    def post(self, url: str, data=None, json=None, headers: dict = None, timeout: int = None, **kwargs) -> Tuple[int, dict, str]:
        return self._request("POST", url, data=data, json=json, headers=headers, timeout=timeout, **kwargs)

    def put(self, url: str, data=None, json=None, headers: dict = None, timeout: int = None, **kwargs) -> Tuple[int, dict, str]:
        return self._request("PUT", url, data=data, json=json, headers=headers, timeout=timeout, **kwargs)

    def delete(self, url: str, headers: dict = None, timeout: int = None, **kwargs) -> Tuple[int, dict, str]:
        return self._request("DELETE", url, headers=headers, timeout=timeout, **kwargs)

    def _request(self, method: str, url: str, timeout: int = None, **kwargs) -> Tuple[int, dict, str]:
        headers = kwargs.pop("headers", None) or DEFAULT_HEADERS.copy()
        request_timeout = timeout or self.timeout
        if self.use_jitter:
            jitter_headers = jitter.get_random_headers(referer=True)
            jitter_headers.update(headers)
            headers = jitter_headers

        last_error = None
        for attempt in range(self.max_retries):
            proxy_dict = None
            if self.use_proxy:
                proxy_dict = proxy_pool.get_proxy(strategy="weighted_random")
                if proxy_dict and proxy_dict.get("http") is None:
                    proxy_dict = None

            start_time = time.time()
            try:
                resp = self._session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    proxies=proxy_dict,
                    timeout=request_timeout,
                    verify=False,
                    **kwargs,
                )
                latency = time.time() - start_time

                if proxy_dict and proxy_dict.get("http"):
                    proxy_pool.report_success(proxy_dict, latency)

                self._request_count += 1
                return resp.status_code, dict(resp.headers), resp.text

            except requests.exceptions.ProxyError as e:
                latency = time.time() - start_time
                if proxy_dict and proxy_dict.get("http"):
                    proxy_pool.report_failure(proxy_dict)
                last_error = e
                log.warning(f"Proxy error (attempt {attempt+1}): {e}")
                if self.use_jitter:
                    jitter.wait(jitter_factor=0.3)

            except requests.exceptions.ConnectTimeout as e:
                latency = time.time() - start_time
                if proxy_dict and proxy_dict.get("http"):
                    proxy_pool.report_failure(proxy_dict)
                last_error = e
                log.warning(f"Connect timeout (attempt {attempt+1}): {e}")

            except requests.exceptions.ReadTimeout as e:
                latency = time.time() - start_time
                last_error = e
                log.warning(f"Read timeout (attempt {attempt+1}): {e}")

            except requests.exceptions.ConnectionError as e:
                latency = time.time() - start_time
                if proxy_dict and proxy_dict.get("http"):
                    proxy_pool.report_failure(proxy_dict)
                last_error = e
                log.warning(f"Connection error (attempt {attempt+1}): {e}")
                if self.use_jitter:
                    jitter.wait(jitter_factor=0.5)

            except requests.RequestException as e:
                latency = time.time() - start_time
                last_error = e
                log.error(f"Request error (attempt {attempt+1}): {e}")

            if self.use_jitter and attempt < self.max_retries - 1:
                jitter.wait(jitter_factor=0.3)

        self._error_count += 1
        return 0, {}, f"Failed after {self.max_retries} attempts: {last_error}"

    def close(self):
        self._session.close()

    def get_stats(self) -> dict:
        return {
            "request_count": self._request_count,
            "error_count": self._error_count,
            "proxy_stats": proxy_pool.stats if self.use_proxy else None,
            "jitter_stats": jitter.get_stats() if self.use_jitter else None,
        }


def http_get(url: str, timeout: int = None, headers: dict = None,
             verify_ssl: bool = False, use_proxy: bool = True, **kwargs) -> Tuple[int, dict, str]:
    client = HTTPClient(use_proxy=use_proxy, use_jitter=True, timeout=timeout)
    try:
        return client.get(url, headers=headers, **kwargs)
    finally:
        client.close()


def http_post(url: str, data=None, json=None, content_type: str = None,
              timeout: int = None, headers: dict = None, verify_ssl: bool = False,
              use_proxy: bool = True, **kwargs) -> Tuple[int, dict, str]:
    client = HTTPClient(use_proxy=use_proxy, use_jitter=True, timeout=timeout)
    try:
        if content_type:
            headers = headers or {}
            headers["Content-Type"] = content_type
        return client.post(url, data=data, json=json, headers=headers, **kwargs)
    finally:
        client.close()


def http_get_no_proxy(url: str, timeout: int = None, headers: dict = None,
                      **kwargs) -> Tuple[int, dict, str]:
    return http_get(url, timeout=timeout, headers=headers, use_proxy=False, **kwargs)
