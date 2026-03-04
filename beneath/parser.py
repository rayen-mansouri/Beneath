from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional


STRACE_LINE = re.compile(
    r"^(?:\[pid\s+(?P<pid>\d+)\]\s+)?"
    r"(?P<ts>\d{2}:\d{2}:\d{2}\.\d{6})\s+"
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"
    r"\((?P<args>.*)\)\s+=\s+"
    r"(?P<ret>.+?)\s+"
    r"<(?P<dur>[0-9.]+)>$"
)


@dataclass(slots=True)
class SyscallEvent:
    raw: str
    pid: Optional[int]
    timestamp: str
    syscall: str
    args: str
    return_value: str
    duration: float
    error: Optional[str]


def _extract_error(ret: str) -> Optional[str]:
    if ret.startswith("-1"):
        parts = ret.split()
        if len(parts) >= 2:
            return parts[1]
        return "ERROR"
    return None


def parse_strace(stderr_text: str) -> List[SyscallEvent]:
    events: List[SyscallEvent] = []
    unfinished: dict[str, str] = {}

    for raw_line in stderr_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if "<unfinished ...>" in line:
            key = line.split(" ", 2)[0]
            unfinished[key] = line
            continue

        if "resumed>" in line:
            continue

        match = STRACE_LINE.match(line)
        if not match:
            continue

        pid_raw = match.group("pid")
        pid = int(pid_raw) if pid_raw else None
        ret = match.group("ret").strip()
        event = SyscallEvent(
            raw=raw_line,
            pid=pid,
            timestamp=match.group("ts"),
            syscall=match.group("name"),
            args=match.group("args"),
            return_value=ret,
            duration=float(match.group("dur")),
            error=_extract_error(ret),
        )
        events.append(event)

    return events


def events_to_rows(events: Iterable[SyscallEvent]) -> List[dict]:
    return [
        {
            "pid": event.pid,
            "timestamp": event.timestamp,
            "syscall": event.syscall,
            "args": event.args,
            "return_value": event.return_value,
            "duration": event.duration,
            "error": event.error,
            "raw": event.raw,
        }
        for event in events
    ]
