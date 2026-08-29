"""Turn raw observations into findings and an overall grade.

The grade starts at the best value and is capped down by each problem, in the
spirit of well known TLS graders. The worst applicable cap wins.
"""
from __future__ import annotations

from .models import Finding, HostAudit

GRADES = ["A+", "A", "B", "C", "D", "F"]

_WEAK_CIPHER_TOKENS = ("RC4", "DES", "CBC3", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH")
# HSTS max-age considered strong: 180 days in seconds.
STRONG_HSTS_SECONDS = 15552000


def is_weak_cipher(name: str) -> bool:
    up = (name or "").upper()
    return any(tok in up for tok in _WEAK_CIPHER_TOKENS)


def has_forward_secrecy(version: str, cipher_name: str) -> bool:
    if version == "TLSv1.3":
        return True
    up = (cipher_name or "").upper()
    return "ECDHE" in up or "DHE" in up


def hsts_max_age(value):
    if not value:
        return None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


def _cap(current: int, grade_label: str) -> int:
    return max(current, GRADES.index(grade_label))


def evaluate(audit: HostAudit, min_expiry_days: int = 30) -> None:
    """Fill audit.findings and audit.grade based on the gathered data."""
    if not audit.reachable:
        audit.grade = "ERR"
        return

    findings = []
    cap = 0  # A+

    # Trust and certificate validity.
    if not audit.trusted:
        reason = audit.trust_reason or "the certificate did not validate"
        low = reason.lower()
        if "expired" in low:
            findings.append(Finding("critical", "Certificate expired", reason,
                                    "Renew the certificate and automate renewal so it cannot lapse."))
        elif "hostname" in low or "match" in low or "subjectaltname" in low:
            findings.append(Finding("critical", "Hostname mismatch", reason,
                                    "Issue a certificate whose subject alternative names cover this host."))
        elif "self" in low and "signed" in low:
            findings.append(Finding("critical", "Self signed certificate", reason,
                                    "Use a certificate from a trusted authority for anything public facing."))
        elif "local issuer" in low or "unable to get" in low or "chain" in low:
            findings.append(Finding("high", "Incomplete chain or unknown issuer", reason,
                                    "Serve the full chain, including intermediates, from a trusted authority."))
        else:
            findings.append(Finding("high", "Certificate not trusted", reason,
                                    "Investigate why the certificate fails validation and reissue if needed."))
        cap = _cap(cap, "F")

    cert = audit.cert
    if cert and cert.days_to_expiry is not None:
        d = cert.days_to_expiry
        if d < 0 and audit.trusted:
            findings.append(Finding("critical", "Certificate expired",
                                    f"Expired {abs(d)} day(s) ago.", "Renew immediately."))
            cap = _cap(cap, "F")
        elif 0 <= d < 7:
            findings.append(Finding("high", "Certificate expiring very soon",
                                    f"Expires in {d} day(s).", "Renew now to avoid an outage."))
            cap = _cap(cap, "C")
        elif 7 <= d < min_expiry_days:
            findings.append(Finding("medium", "Certificate expiring soon",
                                    f"Expires in {d} day(s).",
                                    "Renew ahead of time and automate renewal."))
            cap = _cap(cap, "B")

    # Protocol versions.
    supported = {p.name for p in audit.protocols if p.status == "supported"}
    tested = {p.name for p in audit.protocols if p.status != "untested"}

    if "SSL 3.0" in supported:
        findings.append(Finding("critical", "SSL 3.0 enabled",
                                "The server accepts SSL 3.0, which is broken (POODLE).",
                                "Disable SSL 3.0 entirely."))
        cap = _cap(cap, "F")

    modern = ("TLS 1.2" in supported) or ("TLS 1.3" in supported)
    if not modern and ("TLS 1.2" in tested or "TLS 1.3" in tested):
        findings.append(Finding("critical", "No modern TLS",
                                "Neither TLS 1.2 nor TLS 1.3 is available.",
                                "Enable TLS 1.2 and TLS 1.3."))
        cap = _cap(cap, "F")

    for old in ("TLS 1.0", "TLS 1.1"):
        if old in supported:
            findings.append(Finding("high", f"{old} enabled",
                                    f"The server accepts {old}, which is deprecated.",
                                    f"Disable {old} and require TLS 1.2 or newer."))
            cap = _cap(cap, "C")

    if modern and "TLS 1.3" not in supported and "TLS 1.3" in tested:
        findings.append(Finding("low", "TLS 1.3 not available",
                                "The server does not offer TLS 1.3.",
                                "Enable TLS 1.3 for better security and speed."))
        cap = _cap(cap, "A")

    # Cipher and forward secrecy.
    if audit.negotiated_cipher:
        if is_weak_cipher(audit.negotiated_cipher):
            findings.append(Finding("high", "Weak cipher negotiated",
                                    f"The connection used {audit.negotiated_cipher}.",
                                    "Remove RC4, 3DES, export and null ciphers from the configuration."))
            cap = _cap(cap, "C")
        if not audit.forward_secrecy:
            findings.append(Finding("medium", "No forward secrecy",
                                    f"The negotiated cipher {audit.negotiated_cipher} lacks forward secrecy.",
                                    "Prefer ECDHE key exchange so past sessions stay safe if the key leaks."))
            cap = _cap(cap, "B")

    # HSTS, only meaningful once the certificate is trusted.
    if audit.trusted:
        if audit.hsts is None:
            findings.append(Finding("low", "HSTS not set",
                                    "The response has no Strict Transport Security header.",
                                    "Add Strict-Transport-Security with a long max-age to enforce HTTPS."))
            cap = _cap(cap, "A")
        else:
            ma = hsts_max_age(audit.hsts)
            if ma is not None and ma < STRONG_HSTS_SECONDS:
                findings.append(Finding("low", "HSTS max-age is short",
                                        f"max-age is {ma} seconds.",
                                        "Set max-age to at least 15552000 seconds, which is 180 days."))
                cap = _cap(cap, "A")

    audit.findings = findings
    audit.grade = GRADES[cap]
