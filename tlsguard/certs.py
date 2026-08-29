"""Certificate helpers built on the standard library only.

The ssl module can parse a certificate into a dict, but only after it has been
validated. To inspect certificates that fail validation (expired, self signed,
wrong host) we decode the DER form ourselves using the same internal decoder
the ssl module uses, with a safe fallback when it is not available.
"""
from __future__ import annotations

import hashlib
import os
import ssl
import tempfile
import time
from typing import List, Optional

from .models import CertInfo


def sha256_fingerprint(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2)).upper()


def decode_der(der: bytes) -> dict:
    """Return the ssl style dict for a DER certificate, or an empty dict."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except Exception:
        return {}
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        os.write(fd, pem.encode("ascii", "replace"))
        os.close(fd)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        return {}
    try:
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _rdn_value(seq, key: str) -> str:
    for rdn in seq or ():
        for k, v in rdn:
            if k == key:
                return v
    return ""


def dns_names(cert: dict) -> List[str]:
    names = [v for typ, v in cert.get("subjectAltName", ()) if typ.lower() == "dns"]
    if not names:
        cn = _rdn_value(cert.get("subject"), "commonName")
        if cn:
            names = [cn]
    return names


def _label_match(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip(".")
    host = host.lower().strip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # keep leading dot
        if host.endswith(suffix):
            left = host[: -len(suffix)]
            if left and "." not in left:
                return True
    return False


def hostname_matches(cert: dict, host: str) -> bool:
    return any(_label_match(name, host) for name in dns_names(cert))


def is_self_signed(cert: dict) -> bool:
    subject = cert.get("subject")
    issuer = cert.get("issuer")
    if not subject or not issuer:
        return False
    return subject == issuer


def days_until(not_after: str) -> Optional[int]:
    if not not_after:
        return None
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except Exception:
        return None
    return int((expires - time.time()) // 86400)


def build_cert_info(cert: dict, der: bytes, host: str) -> CertInfo:
    info = CertInfo()
    info.subject_cn = _rdn_value(cert.get("subject"), "commonName")
    info.issuer_cn = _rdn_value(cert.get("issuer"), "commonName")
    info.issuer_org = _rdn_value(cert.get("issuer"), "organizationName")
    info.sans = dns_names(cert)
    info.not_before = cert.get("notBefore", "")
    info.not_after = cert.get("notAfter", "")
    info.days_to_expiry = days_until(info.not_after)
    info.self_signed = is_self_signed(cert)
    info.hostname_match = hostname_matches(cert, host) if info.sans else False
    if der:
        info.fingerprint_sha256 = sha256_fingerprint(der)
    return info
