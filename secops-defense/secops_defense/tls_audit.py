"""TLS 证书审计模块"""
import ssl
import socket
import datetime
from typing import Optional
from secops_core.logger import get_logger

log = get_logger("tls_audit")

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "DES-CBC3", "RC4-SHA", "DES-CBC-SHA",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

STRONG_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]

RECOMMENDED_CIPHERS_TLS13 = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
]


def audit_host(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    result = {
        "hostname": hostname,
        "port": port,
        "certificate": {},
        "protocols": {},
        "ciphers": {},
        "issues": [],
        "score": 100,
        "recommendations": [],
    }

    try:
        cert_info = _get_certificate_info(hostname, port, timeout)
        result["certificate"] = cert_info
        _check_certificate(cert_info, result)
    except Exception as e:
        result["issues"].append(f"Certificate check failed: {e}")
        result["score"] -= 30

    try:
        proto_info = _check_protocols(hostname, port, timeout)
        result["protocols"] = proto_info
        _check_protocol_security(proto_info, result)
    except Exception as e:
        result["issues"].append(f"Protocol check failed: {e}")

    try:
        cipher_info = _check_ciphers(hostname, port, timeout)
        result["ciphers"] = cipher_info
        _check_cipher_security(cipher_info, result)
    except Exception as e:
        result["issues"].append(f"Cipher check failed: {e}")

    result["score"] = max(0, result["score"])

    if result["score"] >= 80:
        result["rating"] = "A"
    elif result["score"] >= 60:
        result["rating"] = "B"
    elif result["score"] >= 40:
        result["rating"] = "C"
    elif result["score"] >= 20:
        result["rating"] = "D"
    else:
        result["rating"] = "F"

    return result


def _get_certificate_info(hostname: str, port: int, timeout: int) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert(binary_form=True)
            cert_text = ssock.getpeercert()

    x509 = ssl._ssl._test_decode_cert(None)
    import ssl as _ssl
    cert_der = cert

    info = {
        "subject": dict(x[0] for x in cert_text.get("subject", [])) if cert_text else {},
        "issuer": dict(x[0] for x in cert_text.get("issuer", [])) if cert_text else {},
        "serialNumber": cert_text.get("serialNumber", "") if cert_text else "",
        "notBefore": cert_text.get("notBefore", "") if cert_text else "",
        "notAfter": cert_text.get("notAfter", "") if cert_text else "",
        "subjectAltName": cert_text.get("subjectAltName", []) if cert_text else [],
        "version": cert_text.get("version", "") if cert_text else "",
    }

    if info["notAfter"]:
        try:
            expire = datetime.datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z")
            info["daysUntilExpiry"] = (expire - datetime.datetime.utcnow()).days
        except Exception:
            info["daysUntilExpiry"] = -1

    return info


def _check_certificate(cert_info: dict, result: dict):
    days = cert_info.get("daysUntilExpiry", -1)
    if days < 0:
        result["issues"].append("Certificate expiry date could not be determined")
        result["score"] -= 10
    elif days < 7:
        result["issues"].append(f"CRITICAL: Certificate expires in {days} days!")
        result["score"] -= 30
    elif days < 30:
        result["issues"].append(f"WARNING: Certificate expires in {days} days")
        result["score"] -= 15
    elif days < 90:
        result["issues"].append(f"INFO: Certificate expires in {days} days")
        result["score"] -= 5

    issuer = cert_info.get("issuer", {})
    if "Let's Encrypt" in str(issuer) or "ISRG" in str(issuer):
        result["recommendations"].append("Consider using a paid certificate for production")

    if not cert_info.get("subjectAltName"):
        result["issues"].append("Certificate missing Subject Alternative Names")
        result["score"] -= 5


def _check_protocols(hostname: str, port: int, timeout: int) -> dict:
    results = {}
    proto_map = {
        "SSLv2": ssl.PROTOCOL_SSLv23,
        "SSLv3": ssl.PROTOCOL_SSLv23,
        "TLSv1": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
    }

    for proto_name, proto_const in proto_map.items():
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if proto_name == "SSLv2":
                ctx.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            elif proto_name == "SSLv3":
                ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            elif proto_name == "TLSv1":
                ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            elif proto_name == "TLSv1.1":
                ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2
            elif proto_name == "TLSv1.2":
                ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results[proto_name] = True
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
            results[proto_name] = False

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                results["TLSv1.3"] = True
    except Exception:
        results["TLSv1.3"] = False

    return results


def _check_ciphers(hostname: str, port: int, timeout: int) -> dict:
    results = {"supported": [], "weak": [], "strong": []}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ciphers = ctx.get_ciphers()

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    results["active_cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }
    except Exception:
        pass

    return results


def _check_protocol_security(proto_info: dict, result: dict):
    for weak_proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
        if proto_info.get(weak_proto):
            result["issues"].append(f"WEAK: {weak_proto} is enabled")
            result["score"] -= 20
            result["recommendations"].append(f"Disable {weak_proto}")

    if not proto_info.get("TLSv1.2") and not proto_info.get("TLSv1.3"):
        result["issues"].append("No modern TLS protocol supported")
        result["score"] -= 15

    if proto_info.get("TLSv1.3"):
        result["recommendations"].append("TLS 1.3 is supported (good)")


def _check_cipher_security(cipher_info: dict, result: dict):
    active = cipher_info.get("active_cipher", {})
    cipher_name = active.get("name", "")
    bits = active.get("bits", 0)

    for weak in WEAK_CIPHERS:
        if weak.lower() in cipher_name.lower():
            result["issues"].append(f"WEAK cipher in use: {cipher_name}")
            result["score"] -= 15
            result["recommendations"].append("Switch to AES-GCM or ChaCha20-Poly1305")
            break

    if 0 < bits < 128:
        result["issues"].append(f"Weak cipher strength: {bits} bits")
        result["score"] -= 10


def audit_url(url: str) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    return audit_host(hostname, port)


def run_tls_audit(target: str = None) -> dict:
    if target:
        return audit_url(target) if target.startswith("http") else audit_host(target)
    import socket
    hostname = socket.gethostname()
    return audit_host(hostname)
