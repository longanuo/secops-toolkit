"""Rootkit / 后门检测模块"""
import os
import subprocess
import hashlib
from typing import List
from secops_core.logger import get_logger

log = get_logger("rootkit_check")

SUID_SGID_PATHS = [
    "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
    "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec", "/usr/bin/crontab",
    "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_unix_chkpwd",
]

SUSPICIOUS_PATHS = [
    "/tmp/.ICE-unix/.x", "/tmp/.font-unix/.x",
    "/dev/shm/.x", "/var/tmp/.ICE-unix",
    "/tmp/.ssh/", "/dev/.udev/rules.d/",
]

KNOWN_ROOTKIT_INDICATORS = [
    {"name": "Reptile", "paths": ["/usr/share/.reptile", "/lib/modules/.reptile"],
     "processes": ["reptile"], "modules": ["reptile"]},
    {"name": "Diamorphine", "processes": [], "modules": ["diamorphine"]},
    {"name": "Jynx2", "paths": ["/usr/share/jynx2", "/tmp/.jynx"],
     "processes": ["jynx2"], "ld_preload": ["libjynx2.so"]},
    {"name": "Adore", "modules": ["adore"]},
    {"name": "Enyelkm", "modules": ["enyelkm"]},
    {"name": "Azazel", "ld_preload": ["libazazel.so"]},
    {"name": "Kovid", "paths": ["/usr/share/.kovid"],
     "processes": ["kovid"], "ld_preload": ["libkovid.so"]},
]

BACKDOOR_INDICATORS = [
    {"name": "SSH authorized_keys tampering", "check": "check_ssh_keys"},
    {"name": "Suspicious cron jobs", "check": "check_cron_backdoors"},
    {"name": "Modified system binaries", "check": "check_binary_integrity"},
    {"name": "Hidden processes", "check": "check_hidden_processes"},
    {"name": "Suspicious network connections", "check": "check_backdoor_connections"},
    {"name": "LD_PRELOAD hijacking", "check": "check_ld_preload"},
]


def run_rootkit_check() -> dict:
    result = {
        "suid_sgid": [],
        "suspicious_files": [],
        "rootkit_indicators": [],
        "backdoor_indicators": [],
        "kernel_modules": [],
        "issues": [],
        "score": 100,
    }

    _check_suid_sgid(result)
    _check_suspicious_paths(result)
    _check_rootkit_indicators(result)
    _check_kernel_modules(result)
    _check_ld_preload(result)
    _check_hidden_processes(result)
    _check_binary_integrity(result)
    _check_cron_backdoors(result)
    _check_ssh_keys(result)
    _check_backdoor_connections(result)

    result["score"] = max(0, result["score"])
    return result


def _check_suid_sgid(result: dict):
    try:
        output = subprocess.check_output(
            ["find", "/", "-perm", "-4000", "-o", "-perm", "-2000"],
            stderr=subprocess.DEVNULL, timeout=30
        ).decode("utf-8", errors="replace")
        suid_files = [f.strip() for f in output.strip().split("\n") if f.strip()]
        unexpected = [f for f in suid_files if f not in SUID_SGID_PATHS]
        result["suid_sgid"] = suid_files
        if unexpected:
            result["issues"].append(f"Found {len(unexpected)} unexpected SUID/SGID files")
            result["score"] -= 10
    except Exception as e:
        log.debug(f"SUID check failed: {e}")


def _check_suspicious_paths(result: dict):
    found = []
    for path in SUSPICIOUS_PATHS:
        if os.path.exists(path):
            found.append(path)
            result["issues"].append(f"Suspicious path exists: {path}")
            result["score"] -= 5
    result["suspicious_files"] = found


def _check_rootkit_indicators(result: dict):
    indicators = []
    for rk in KNOWN_ROOTKIT_INDICATORS:
        found = False
        for path in rk.get("paths", []):
            if os.path.exists(path):
                indicators.append({"name": rk["name"], "type": "path", "location": path})
                found = True
        for proc in rk.get("processes", []):
            try:
                out = subprocess.check_output(["pgrep", "-f", proc],
                                              stderr=subprocess.DEVNULL).decode()
                if out.strip():
                    indicators.append({"name": rk["name"], "type": "process", "pid": out.strip()})
                    found = True
            except Exception:
                pass
        for mod in rk.get("modules", []):
            try:
                out = subprocess.check_output(["lsmod"], stderr=subprocess.DEVNULL).decode()
                if mod in out:
                    indicators.append({"name": rk["name"], "type": "module", "module": mod})
                    found = True
            except Exception:
                pass
        if found:
            result["issues"].append(f"Rootkit indicator: {rk['name']}")
            result["score"] -= 25
    result["rootkit_indicators"] = indicators


def _check_kernel_modules(result: dict):
    try:
        out = subprocess.check_output(["lsmod"], stderr=subprocess.DEVNULL).decode()
        modules = []
        for line in out.strip().split("\n")[1:]:
            parts = line.split()
            if parts:
                modules.append(parts[0])
        result["kernel_modules"] = modules
        suspicious = [m for m in modules if m not in [
            "ext4", "xfs", "btrfs", "vfat", "fuse", "overlay",
            "nfs", "cifs", "usbcore", "uhid", "hid", "bluetooth",
            "btusb", "intel_powerclamp", "kvm", "kvm_intel",
        ]]
        if len(suspicious) > 10:
            result["issues"].append(f"Unusual number of loaded kernel modules: {len(suspicious)}")
            result["score"] -= 5
    except Exception:
        pass


def _check_ld_preload(result: dict):
    ld_preload = os.environ.get("LD_PRELOAD", "")
    if ld_preload:
        result["issues"].append(f"LD_PRELOAD is set: {ld_preload}")
        result["score"] -= 20
        return

    suspicious_libs = []
    for lib_path in ["/etc/ld.so.preload", "/etc/ld.so.conf.d/"]:
        if os.path.isfile(lib_path):
            try:
                with open(lib_path) as f:
                    content = f.read()
                if content.strip():
                    suspicious_libs.append({"file": lib_path, "content": content.strip()[:200]})
            except Exception:
                pass
    if suspicious_libs:
        result["issues"].append("Suspicious LD_PRELOAD configuration found")
        result["score"] -= 15


def _check_hidden_processes(result: dict):
    try:
        ps_out = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL).decode()
        proc_files = os.listdir("/proc")
        pids_in_proc = [p for p in proc_files if p.isdigit()]
        pids_in_ps = []
        for line in ps_out.strip().split("\n")[1:]:
            parts = line.split()
            if parts and parts[1].isdigit():
                pids_in_ps.append(parts[1])

        hidden = set(pids_in_proc) - set(pids_in_ps)
        hidden.discard("1")
        if hidden:
            result["issues"].append(f"Hidden processes detected: {list(hidden)[:5]}")
            result["score"] -= 20
    except Exception as e:
        log.debug(f"Hidden process check failed: {e}")


def _check_binary_integrity(result: dict):
    critical_bins = ["/usr/bin/ls", "/usr/bin/ps", "/usr/bin/netstat",
                     "/usr/bin/ss", "/usr/bin/top", "/usr/bin/find"]
    modified = []
    for binary in critical_bins:
        if os.path.exists(binary):
            try:
                with open(binary, "rb") as f:
                    h = hashlib.sha256(f.read()).hexdigest()
                dpkg_out = subprocess.check_output(
                    ["dpkg", "-S", binary], stderr=subprocess.DEVNULL
                ).decode()
                if "diversion" in dpkg_out.lower():
                    modified.append(binary)
            except Exception:
                pass
    if modified:
        result["issues"].append(f"Modified critical binaries: {modified}")
        result["score"] -= 10


def _check_cron_backdoors(result: dict):
    cron_dirs = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
    suspicious = []
    for cron_path in cron_dirs:
        if os.path.isfile(cron_path):
            try:
                with open(cron_path) as f:
                    content = f.read()
                for line in content.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if any(s in line for s in ["curl ", "wget ", "python", "perl", "nc ", "ncat "]):
                            suspicious.append({"file": cron_path, "line": line[:200]})
            except Exception:
                pass
    if suspicious:
        result["issues"].append(f"Suspicious cron entries: {len(suspicious)}")
        result["score"] -= 10


def _check_ssh_keys(result: dict):
    home = os.path.expanduser("~")
    auth_keys = os.path.join(home, ".ssh", "authorized_keys")
    if os.path.exists(auth_keys):
        try:
            with open(auth_keys) as f:
                keys = [l.strip() for l in f.readlines() if l.strip() and not l.startswith("#")]
            if len(keys) > 5:
                result["issues"].append(f"Unusual number of SSH keys: {len(keys)}")
                result["score"] -= 5
            result["backdoor_indicators"].append({
                "type": "ssh_keys",
                "count": len(keys),
                "file": auth_keys,
            })
        except Exception:
            pass


def _check_backdoor_connections(result: dict):
    try:
        out = subprocess.check_output(
            ["ss", "-tlnp"], stderr=subprocess.DEVNULL
        ).decode()
        suspicious_ports = []
        for line in out.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                if ":" in local:
                    port = int(local.rsplit(":", 1)[1])
                    if port in [4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345]:
                        suspicious_ports.append(port)
        if suspicious_ports:
            result["issues"].append(f"Suspicious listening ports: {suspicious_ports}")
            result["score"] -= 15
    except Exception:
        pass
