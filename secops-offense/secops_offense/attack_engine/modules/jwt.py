"""JWT 漏洞检测器"""
import re
import time
import base64
import json
import urllib.parse
from typing import List
from secops_core.http_client import http_get, http_post
from secops_core.config import ATTACK_DELAY
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.auth import log_audit
from secops_offense.attack_engine.modules.base import BaseDetector


class JWTDetector(BaseDetector):
    """JWT (JSON Web Token) 漏洞检测器"""

    name = "jwt"
    category = "JWT"

    ALGORITHM_CONFUSION_PAYLOADS = [
        "none",
        "None",
        "NONE",
        "nOnE",
    ]

    COMMON_SECRETS = [
        "secret",
        "123456",
        "password",
        "admin",
        "jwt_secret",
        "supersecret",
        "your-256-bit-secret",
        "shhhhh",
        "keyboard cat",
    ]

    def _decode_jwt_payload(self, token):
        """解码 JWT payload"""
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                payload = parts[1]
                # 补齐 padding
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += '=' * padding
                decoded = base64.urlsafe_b64decode(payload)
                return json.loads(decoded)
        except Exception:
            pass
        return None

    def _find_jwt_tokens(self, response_text):
        """在响应中查找 JWT token"""
        jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'
        return re.findall(jwt_pattern, response_text)

    def test(self, target_url: str, params: list = None) -> List[Finding]:
        findings = []

        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 1. 检查响应头中的 JWT
        log_audit("JWT_HEADER", base_url, "Checking response headers for JWT")
        status, headers, body = http_get(base_url, timeout=8)

        if status == 0:
            return findings

        # 检查 Set-Cookie 中的 JWT
        jwt_tokens = []
        for header_name, header_value in headers.items():
            if 'jwt' in header_name.lower() or 'token' in header_name.lower():
                if 'eyJ' in str(header_value):
                    jwt_tokens.append(str(header_value))

        # 检查响应体中的 JWT
        body_tokens = self._find_jwt_tokens(body)
        jwt_tokens.extend(body_tokens)

        if not jwt_tokens:
            return findings

        # 2. 分析找到的 JWT token
        for token in jwt_tokens[:3]:  # 最多分析3个
            payload = self._decode_jwt_payload(token)
            if not payload:
                continue

            # 检查算法
            header_parts = token.split('.')
            if len(header_parts) >= 1:
                try:
                    header_padding = 4 - len(header_parts[0]) % 4
                    if header_padding != 4:
                        header_str = header_parts[0] + '=' * header_padding
                    else:
                        header_str = header_parts[0]
                    header_decoded = json.loads(base64.urlsafe_b64decode(header_str))
                    algorithm = header_decoded.get('alg', '')

                    # 检测算法混淆漏洞
                    if algorithm.upper() == 'NONE':
                        findings.append(Finding(
                            vuln_type="JWT", severity="critical",
                            title="JWT 算法混淆漏洞 (alg=none)",
                            location=base_url, payload=f"Algorithm: {algorithm}",
                            evidence=f"JWT 使用 none 算法，可伪造任意 token",
                            description="JWT 使用 none 算法，攻击者可伪造任意 token 绕过认证。",
                            remediation="服务端必须验证 JWT 算法，禁止接受 none 算法"
                        ))

                    # 检测弱密钥
                    if algorithm.startswith('HS'):
                        for secret in self.COMMON_SECRETS:
                            # 简单检查 token 是否可被常见密钥验证
                            if secret in body.lower():
                                findings.append(Finding(
                                    vuln_type="JWT", severity="high",
                                    title="JWT 弱密钥风险",
                                    location=base_url, payload=f"Algorithm: {algorithm}",
                                    evidence=f"JWT 可能使用弱密钥",
                                    description="JWT 可能使用常见弱密钥，建议使用强随机密钥。",
                                    remediation="使用至少 256 位的随机密钥"
                                ))
                                break

                except Exception:
                    pass

            # 检查 payload 中的敏感信息
            if payload:
                sensitive_keys = ['password', 'secret', 'token', 'api_key', 'apikey']
                for key in payload:
                    if any(s in key.lower() for s in sensitive_keys):
                        findings.append(Finding(
                            vuln_type="JWT", severity="medium",
                            title="JWT 包含敏感信息",
                            location=base_url, payload=f"Key: {key}",
                            evidence=f"JWT payload 中包含敏感字段: {key}",
                            description=f"JWT payload 中包含敏感信息字段 '{key}'。",
                            remediation="不要在 JWT 中存储敏感信息"
                        ))

        return findings
