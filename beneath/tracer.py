from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import List


@dataclass(slots=True)
class TraceResult:
    command: List[str]
    return_code: int
    stderr: str
    stdout: str


class TraceError(RuntimeError):
    pass


def _ensure_linux_strace() -> None:
    if shutil.which("strace") is None:
        raise TraceError("strace not found. Install it first (e.g., apt install strace).")


def run_strace(command: List[str]) -> TraceResult:
    if not command:
        raise TraceError("No command provided.")
    _ensure_linux_strace()

    wrapped = ["strace", "-f", "-tt", "-T", *command]
    process = subprocess.run(
        wrapped,
        capture_output=True,
        text=True,
        check=False,
    )
    return TraceResult(
        command=command,
        return_code=process.returncode,
        stderr=process.stderr,
        stdout=process.stdout,
    )
