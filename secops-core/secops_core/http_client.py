"""统一 HTTP 请求封装 — 增强版"""
import requests
import urllib3
from typing import Tuple
from secops_core.config import HTTP_TIMEOUT, HTTP_USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {"User-Agent": HTTP_USER_AGENT}


def _get_proxies():
    import os
    proxy = os.environ.get("SECOPS_PROXY") or os.environ.get("HTTP_PROXY")
    if proxy:
        return {"http": proxy, "https": proxy}
    return None


def http_get(url: str, timeout: int = None, headers: dict = None,
             verify_ssl: bool = False, **kwargs) -> Tuple[int, dict, str]:
    timeout = timeout or HTTP_TIMEOUT
    headers = headers or DEFAULT_HEADERS.copy()
    kwargs.setdefault("proxies", _get_proxies())
    try:
        resp = requests.get(url, headers=headers, timeout=timeout,
                            verify=verify_ssl, **kwargs)
        return resp.status_code, dict(resp.headers), resp.text
    except requests.RequestException as e:
        return 0, {}, str(e)


def http_post(url: str, data=None, json=None, content_type: str = None,
              timeout: int = None, headers: dict = None, verify_ssl: bool = False,
              **kwargs) -> Tuple[int, dict, str]:
    timeout = timeout or HTTP_TIMEOUT
    headers = headers or DEFAULT_HEADERS.copy()
    if content_type:
        headers["Content-Type"] = content_type
    kwargs.setdefault("proxies", _get_proxies())
    try:
        resp = requests.post(url, data=data, json=json, headers=headers,
                             timeout=timeout, verify=verify_ssl, **kwargs)
        return resp.status_code, dict(resp.headers), resp.text
    except requests.RequestException as e:
        return 0, {}, str(e)


def http_get_enhanced(url: str, **kwargs) -> Tuple[int, dict, str]:
    from secops_core.http_client_enhanced import http_get as enhanced_get
    return enhanced_get(url, **kwargs)


def http_post_enhanced(url: str, **kwargs) -> Tuple[int, dict, str]:
    from secops_core.http_client_enhanced import http_post as enhanced_post
    return enhanced_post(url, **kwargs)
