"""Render audit results as text or json."""
from __future__ import annotations

import json
from typing import List

from .models import HostAudit

_COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "green": "\033[32m", "teal": "\033[36m", "yellow": "\033[33m",
    "red": "\033[31m", "bred": "\033[1;31m",
}

_GRADE_COLOR = {
    "A+": "green", "A": "green", "B": "teal", "C": "yellow",
    "D": "yellow", "F": "bred", "ERR": "red", "?": "dim",
}

_SEV_COLOR = {
    "critical": "bred", "high": "red", "medium": "yellow", "low": "teal", "info": "dim",
}


def _c(key: str, on: bool) -> str:
    return _COLORS.get(key, "") if on else ""


def _protocol_cell(name: str, status: str, on: bool) -> str:
    old = name in ("SSL 3.0", "TLS 1.0", "TLS 1.1")
    if status == "untested":
        color = "dim"
    elif old:
        color = "red" if status == "supported" else "dim"
    else:
        color = "green" if status == "supported" else "red"
    word = {"supported": "on", "refused": "off", "untested": "untested"}[status]
    return f"{name} {_c(color, on)}{word}{_c('reset', on)}"


def _host_block(a: HostAudit, on: bool) -> List[str]:
    reset = _c("reset", on)
    gcolor = _GRADE_COLOR.get(a.grade, "dim")
    head = f"{_c('bold', on)}{a.host}:{a.port}{reset}   {_c(gcolor, on)}{_c('bold', on)}{a.grade}{reset}"
    lines = [head]

    if not a.reachable:
        lines.append(f"  {_c('red', on)}unreachable{reset}  {a.error}")
        return lines

    trust = f"{_c('green', on)}trusted{reset}" if a.trusted else f"{_c('red', on)}not trusted{reset}  {a.trust_reason}"
    lines.append(f"  Trust        {trust}")

    if a.cert:
        c = a.cert
        issuer = c.issuer_org or c.issuer_cn or "unknown issuer"
        exp = ""
        if c.days_to_expiry is not None:
            when = c.not_after.replace(" GMT", "")
            exp = f", expires in {c.days_to_expiry} day(s) ({when})"
        lines.append(f"  Certificate  issued by {issuer}{exp}")
        if c.sans:
            shown = ", ".join(c.sans[:4]) + (" ..." if len(c.sans) > 4 else "")
            match = f"{_c('green', on)}matches host{reset}" if c.hostname_match else f"{_c('red', on)}does not match host{reset}"
            lines.append(f"               covers {shown}  [{match}]")
        if c.self_signed:
            lines.append(f"               {_c('yellow', on)}self signed{reset}")

    if a.protocols:
        cells = "   ".join(_protocol_cell(p.name, p.status, on) for p in a.protocols)
        lines.append(f"  Protocols    {cells}")

    if a.negotiated_cipher:
        pfs = f"{_c('green', on)}forward secrecy{reset}" if a.forward_secrecy else f"{_c('red', on)}no forward secrecy{reset}"
        lines.append(f"  Cipher       {a.negotiated_version}  {a.negotiated_cipher}  [{pfs}]")

    if a.hsts is not None:
        lines.append(f"  HSTS         {a.hsts}")
    elif a.trusted:
        lines.append(f"  HSTS         {_c('dim', on)}not set{reset}")

    if a.findings:
        lines.append(f"  {_c('bold', on)}Findings{reset}")
        for f in a.findings:
            sc = _SEV_COLOR.get(f.severity, "dim")
            lines.append(f"    {_c(sc, on)}{f.severity.upper():<8}{reset} {f.title}")
            lines.append(f"             {_c('dim', on)}{f.remediation}{reset}")
    else:
        lines.append(f"  {_c('green', on)}No issues found.{reset}")
    return lines


def format_text(audits: List[HostAudit], use_color: bool = False) -> str:
    on = use_color
    blocks = []
    for a in audits:
        blocks.append("\n".join(_host_block(a, on)))
    body = "\n\n".join(blocks)

    counts = {}
    for a in audits:
        counts[a.grade] = counts.get(a.grade, 0) + 1
    order = ["A+", "A", "B", "C", "D", "F", "ERR"]
    parts = [f"{counts[g]} {g}" for g in order if counts.get(g)]
    summary = f"{_c('bold', on)}{len(audits)} host(s){_c('reset', on)}: " + ", ".join(parts) if parts else ""
    return body + "\n\n" + summary if summary else body


def format_json(audits: List[HostAudit], version: str) -> str:
    payload = {
        "tool": "tlsguard",
        "version": version,
        "hosts": [a.to_dict() for a in audits],
    }
    return json.dumps(payload, indent=2)
