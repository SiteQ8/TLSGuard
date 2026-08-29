"""Orchestrate a full TLS audit of one host."""
from __future__ import annotations

import socket
import ssl
from typing import Optional, Tuple

from . import grading
from .certs import build_cert_info, decode_der
from .models import HostAudit
from .protocols import probe_all

DEFAULT_PORT = 443


def parse_target(target: str, default_port: int = DEFAULT_PORT) -> Tuple[str, int]:
    """Turn user input such as example.com, example.com:8443, or a url into
    a host and port pair."""
    target = target.strip()
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target.startswith("[") and "]" in target:  # bracketed IPv6
        host, _, rest = target[1:].partition("]")
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, default_port
        return host, default_port
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return target, default_port
    return target, default_port


def _tcp_reachable(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _verified_handshake(host: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True, "", ssock.version(), ssock.cipher()
    except ssl.SSLCertVerificationError as exc:
        return False, (getattr(exc, "verify_message", "") or str(exc)), "", None
    except ssl.SSLError as exc:
        return False, (getattr(exc, "reason", "") or str(exc)), "", None
    except (socket.timeout, TimeoutError):
        return False, "connection timed out", "", None
    except OSError as exc:
        return False, str(exc), "", None


def _cert_and_params(host: str, port: int, timeout: float):
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True), ssock.version(), ssock.cipher()
    except Exception:
        return None, "", None


def _fetch_hsts(host: str, port: int, timeout: float) -> Optional[str]:
    ctx = ssl._create_unverified_context()
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "User-Agent: TLSGuard\r\n"
        "Accept: */*\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(request.encode("ascii", "replace"))
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        for line in head.split("\r\n"):
            if line.lower().startswith("strict-transport-security:"):
                return line.split(":", 1)[1].strip()
        return None
    except Exception:
        return None


def audit_host(host: str, port: int = DEFAULT_PORT, timeout: float = 8.0,
               min_expiry_days: int = 30, check_protocols: bool = True,
               check_hsts: bool = True) -> HostAudit:
    """Run a full audit and return a HostAudit with findings and a grade."""
    audit = HostAudit(host=host, port=port)

    if not _tcp_reachable(host, port, timeout):
        audit.reachable = False
        audit.error = "could not connect"
        grading.evaluate(audit, min_expiry_days)
        return audit
    audit.reachable = True

    trusted, reason, v1, c1 = _verified_handshake(host, port, timeout)
    audit.trusted = trusted
    audit.trust_reason = reason

    der, v2, c2 = _cert_and_params(host, port, timeout)
    version = v1 or v2
    cipher = c1 or c2
    if cipher:
        audit.negotiated_version = version
        audit.negotiated_cipher = cipher[0]
    audit.forward_secrecy = grading.has_forward_secrecy(version, audit.negotiated_cipher)

    if der:
        audit.cert = build_cert_info(decode_der(der), der, host)

    if check_protocols:
        audit.protocols = probe_all(host, port, timeout)
    if check_hsts:
        audit.hsts = _fetch_hsts(host, port, timeout)

    grading.evaluate(audit, min_expiry_days)
    return audit
