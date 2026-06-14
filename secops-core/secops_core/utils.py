"""基础工具函数"""
import os
import sys
import subprocess
import platform


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if is_windows():
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def run_cmd(args, shell=False, capture_output=True, text=True, timeout=None):
    try:
        result = subprocess.run(args, shell=shell,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=text, errors="ignore", timeout=timeout)
        return (result.returncode,
                result.stdout if capture_output else "",
                result.stderr if capture_output else "")
    except subprocess.TimeoutExpired as te:
        stdout_r = te.stdout if te.stdout else ""
        stderr_r = te.stderr if te.stderr else ""
        if isinstance(stdout_r, bytes): stdout_r = stdout_r.decode("utf-8", errors="ignore")
        if isinstance(stderr_r, bytes): stderr_r = stderr_r.decode("utf-8", errors="ignore")
        return -1, stdout_r, f"命令执行超时 ({timeout}秒): {str(te)}\n{stderr_r}"
    except Exception as e:
        return -1, "", str(e)


def run_ps_cmd(command, capture_output=True, timeout=30):
    if not is_windows():
        return -1, "", "PowerShell 仅在 Windows 系统中可用"
    args = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
    return run_cmd(args, shell=False, capture_output=capture_output, text=True, timeout=timeout)


def get_proxies() -> dict:
    proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    proxies = {}
    if proxy: proxies["http"] = proxy
    if https_proxy: proxies["https"] = https_proxy
    return proxies
