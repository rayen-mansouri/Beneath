from __future__ import annotations

from dataclasses import dataclass
from typing import List

import pandas as pd


SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass(slots=True)
class SecurityAlert:
    severity: str
    title: str
    detail: str
    syscall: str


def _is_write_like(syscall: str, args: str) -> bool:
    if syscall in {"write", "pwrite64"}:
        return True
    if syscall in {"open", "openat", "creat"}:
        flags = args.upper()
        return any(flag in flags for flag in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC"])
    return False


def detect_security_alerts(frame: pd.DataFrame) -> List[SecurityAlert]:
    alerts: List[SecurityAlert] = []

    if frame.empty:
        return alerts

    for row in frame.itertuples():
        args = str(row.args)
        syscall = str(row.syscall)

        if "/etc/shadow" in args:
            alerts.append(SecurityAlert("CRITICAL", "Shadow file access", row.raw, syscall))

        if "/root/" in args or args.strip().startswith('"/root"'):
            alerts.append(SecurityAlert("HIGH", "Root directory access", row.raw, syscall))

        if syscall == "setuid" and args.strip().startswith("0"):
            alerts.append(SecurityAlert("CRITICAL", "Privilege escalation", row.raw, syscall))

        if syscall == "capset":
            alerts.append(SecurityAlert("HIGH", "Capability change", row.raw, syscall))

        if syscall in {"socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg"}:
            alerts.append(SecurityAlert("MEDIUM", "Network activity", row.raw, syscall))

        if _is_write_like(syscall, args) and any(
            p in args for p in ["/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/root/"]
        ):
            alerts.append(SecurityAlert("HIGH", "Write to system directory", row.raw, syscall))

        if syscall == "execve" and '"' in args:
            first = args.split('"')
            binary = first[1] if len(first) > 1 else ""
            if binary and not binary.startswith(("/bin/", "/usr/bin/", "/usr/sbin/", "/sbin/")):
                alerts.append(SecurityAlert("MEDIUM", "Unexpected binary execution", row.raw, syscall))

    dedup: dict[tuple[str, str, str], SecurityAlert] = {}
    for alert in alerts:
        key = (alert.severity, alert.title, alert.detail)
        dedup[key] = alert

    ordered = sorted(
        dedup.values(),
        key=lambda a: (-SEVERITY_WEIGHT.get(a.severity, 0), a.title),
    )
    return ordered
