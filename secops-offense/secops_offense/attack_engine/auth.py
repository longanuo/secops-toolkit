"""授权门禁模块"""
from datetime import datetime
from secops_core.logger import get_logger

log = get_logger("attack_auth")

_authorization_granted = False
_authorized_target = None
_audit_log = []


def request_authorization(target_url):
    global _authorization_granted, _authorized_target
    print("\n" + "=" * 60)
    print("  [授权确认] 漏洞自动验证引擎")
    print("=" * 60)
    print(f"  目标: {target_url}")
    print()
    print("  本引擎将向目标发送攻击性探测请求，包括：")
    print("  - XSS payload 注入 / SQL 注入探测 / 模板注入检测")
    print("  - 文件包含/路径穿越检测 / 信息泄露扫描")
    print()
    print("  法律声明：未经授权对他人系统进行渗透测试属于违法行为。")
    print()
    ack = input("  确认已获得授权并继续？(输入 yes 确认): ").strip().lower()
    if ack == "yes":
        _authorization_granted = True
        _authorized_target = target_url
        log_audit("AUTH_GRANTED", target_url, "用户确认授权")
        print("  [OK] 授权已确认。\\n")
        return True
    else:
        _authorization_granted = False
        log_audit("AUTH_DENIED", target_url, "用户拒绝授权")
        print("  [拒绝] 未授权，操作已取消。\\n")
        return False


def check_auth(target_url):
    if not _authorization_granted:
        print("  [ERROR] 未授权！请先调用 request_authorization()")
        return False
    if _authorized_target and target_url not in _authorized_target:
        print(f"  [ERROR] 目标不在授权范围内")
        return False
    return True


def log_audit(action, target, detail):
    _audit_log.append({
        "timestamp": datetime.now().isoformat(),
        "action": action, "target": target, "detail": detail
    })


def get_audit_log():
    return _audit_log


def set_authorized(target_url):
    global _authorization_granted, _authorized_target
    _authorization_granted = True
    _authorized_target = target_url
