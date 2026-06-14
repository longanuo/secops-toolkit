"""漏洞自动验证引擎"""
from secops_offense.attack_engine.engine import AttackEngine, start_attack
from secops_offense.attack_engine.auth import request_authorization
from secops_offense.attack_engine.finding import Finding
from secops_offense.attack_engine.modules.xss import XSSDetector
from secops_offense.attack_engine.modules.sqli import SQLiDetector
from secops_offense.attack_engine.modules.ssti import SSTIDetector
from secops_offense.attack_engine.modules.lfi import LFIDetector
from secops_offense.attack_engine.modules.infoleak import InfoLeakDetector
from secops_offense.attack_engine.modules.ssrf import SSRFDetector
from secops_offense.attack_engine.modules.xxe import XXEDetector
from secops_offense.attack_engine.modules.rce import RCEDetector
from secops_offense.attack_engine.modules.nosqli import NoSQLiDetector
from secops_offense.attack_engine.modules.jwt import JWTDetector
from secops_offense.attack_engine.modules.idor import IDORDetector
from secops_offense.attack_engine.modules.cors import CORSDetector
from secops_offense.attack_engine.modules.redirect import RedirectDetector
from secops_offense.attack_engine.modules.ldap import LDAPDetector
from secops_offense.attack_engine.modules.deserialization import DeserializationDetector
from secops_offense.attack_engine.modules.crlf import CRLFDetector
from secops_offense.attack_engine.modules.subdomain_takeover import SubdomainTakeoverDetector

ALL_DETECTORS = {
    "xss": XSSDetector,
    "sqli": SQLiDetector,
    "ssti": SSTIDetector,
    "lfi": LFIDetector,
    "infoleak": InfoLeakDetector,
    "ssrf": SSRFDetector,
    "xxe": XXEDetector,
    "rce": RCEDetector,
    "nosqli": NoSQLiDetector,
    "jwt": JWTDetector,
    "idor": IDORDetector,
    "cors": CORSDetector,
    "redirect": RedirectDetector,
    "ldap": LDAPDetector,
    "deserialization": DeserializationDetector,
    "crlf": CRLFDetector,
    "subdomain_takeover": SubdomainTakeoverDetector,
}

__all__ = [
    "AttackEngine", "start_attack", "request_authorization", "Finding",
    "XSSDetector", "SQLiDetector", "SSTIDetector", "LFIDetector", "InfoLeakDetector",
    "SSRFDetector", "XXEDetector", "RCEDetector", "NoSQLiDetector",
    "JWTDetector", "IDORDetector", "CORSDetector", "RedirectDetector",
    "LDAPDetector", "DeserializationDetector", "CRLFDetector", "SubdomainTakeoverDetector",
    "ALL_DETECTORS",
]
