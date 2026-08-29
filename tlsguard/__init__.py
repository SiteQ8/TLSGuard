"""TLSGuard: audit and harden the TLS posture of your endpoints.

Public entry points:
    from tlsguard import audit_host, __version__
"""
from __future__ import annotations

__version__ = "0.1.0"

from .models import CertInfo, Finding, HostAudit, ProtocolResult  # noqa: E402
from .audit import audit_host  # noqa: E402

__all__ = [
    "__version__",
    "audit_host",
    "HostAudit",
    "CertInfo",
    "ProtocolResult",
    "Finding",
]
