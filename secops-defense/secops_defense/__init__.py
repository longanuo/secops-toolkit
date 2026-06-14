"""SecOps Defense - 系统维护子项目"""
__version__ = "3.0.0"

from .remediation import RemediationEngine, generate_waf_rules, suggest_hardening
from .tls_audit import audit_host, audit_url, run_tls_audit
from .rootkit_check import run_rootkit_check
