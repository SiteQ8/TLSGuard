"""Plain data models used across TLSGuard."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CertInfo:
    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    sans: List[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: Optional[int] = None
    self_signed: bool = False
    hostname_match: bool = False
    fingerprint_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "subject_cn": self.subject_cn,
            "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org,
            "sans": self.sans,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_to_expiry": self.days_to_expiry,
            "self_signed": self.self_signed,
            "hostname_match": self.hostname_match,
            "fingerprint_sha256": self.fingerprint_sha256,
        }


@dataclass
class ProtocolResult:
    name: str
    status: str   # supported | refused | untested

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status}


@dataclass
class Finding:
    severity: str   # critical | high | medium | low | info
    title: str
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class HostAudit:
    host: str
    port: int = 443
    reachable: bool = False
    trusted: bool = False
    trust_reason: str = ""
    negotiated_version: str = ""
    negotiated_cipher: str = ""
    forward_secrecy: bool = False
    protocols: List[ProtocolResult] = field(default_factory=list)
    cert: Optional[CertInfo] = None
    hsts: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    grade: str = "?"
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "grade": self.grade,
            "reachable": self.reachable,
            "trusted": self.trusted,
            "trust_reason": self.trust_reason,
            "negotiated_version": self.negotiated_version,
            "negotiated_cipher": self.negotiated_cipher,
            "forward_secrecy": self.forward_secrecy,
            "protocols": [p.to_dict() for p in self.protocols],
            "certificate": self.cert.to_dict() if self.cert else None,
            "hsts": self.hsts,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }
