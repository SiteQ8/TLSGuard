"""Probe which TLS protocol versions an endpoint accepts.

For each version we open a connection that is pinned to exactly that version.
A successful handshake means the server supports it. A rejected handshake means
the server refused it, which is the safe outcome for old versions. When the
local TLS library cannot offer a version at all, we report it as untested
rather than pretending the server refused it.
"""
from __future__ import annotations

import socket
import ssl
import warnings
from typing import List

from .models import ProtocolResult

# Ordered oldest to newest. Some names may be missing on very old builds.
_VERSION_NAMES = [
    ("SSL 3.0", "SSLv3"),
    ("TLS 1.0", "TLSv1"),
    ("TLS 1.1", "TLSv1_1"),
    ("TLS 1.2", "TLSv1_2"),
    ("TLS 1.3", "TLSv1_3"),
]

# Errors that mean the local library, not the server, declined the version.
_LOCAL_LIMITS = {"NO_PROTOCOLS_AVAILABLE"}


def _supported_versions():
    out = []
    for label, attr in _VERSION_NAMES:
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is not None:
            out.append((label, ver))
    return out


def probe_protocol(host: str, port: int, version, timeout: float) -> str:
    ctx = ssl._create_unverified_context()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, OSError):
        return "untested"

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return "supported" if ssock.version() else "supported"
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", "") or ""
        if reason in _LOCAL_LIMITS:
            return "untested"
        return "refused"
    except (socket.timeout, TimeoutError):
        return "refused"
    except OSError:
        return "refused"


def probe_all(host: str, port: int, timeout: float) -> List[ProtocolResult]:
    results = []
    for label, version in _supported_versions():
        results.append(ProtocolResult(label, probe_protocol(host, port, version, timeout)))
    return results
