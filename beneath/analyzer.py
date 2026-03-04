from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib.pyplot as plt
import pandas as pd

from .parser import SyscallEvent, events_to_rows


CATEGORY_MAP = {
    "File System": {"openat", "read", "write", "access", "getdents64", "stat", "lstat", "fstat", "close"},
    "Process": {"execve", "fork", "vfork", "clone", "wait4", "exit", "exit_group"},
    "Memory": {"mmap", "munmap", "brk", "mprotect", "madvise"},
    "Network": {"socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg", "bind", "accept", "listen"},
    "Privilege / Security": {"setuid", "setgid", "prctl", "capset", "capget"},
    "Terminal I/O": {"ioctl", "write"},
}


@dataclass(slots=True)
class AnalysisResult:
    frame: pd.DataFrame
    summary: Dict[str, str]
    syscall_counts: pd.Series
    category_counts: pd.Series
    timeline: pd.DataFrame
    explanation_steps: List[str]


def categorize_syscall(syscall: str, args: str) -> str:
    for category, names in CATEGORY_MAP.items():
        if syscall in names:
            if category == "Terminal I/O" and syscall == "write" and not args.startswith("1,"):
                continue
            return category
    return "Other"


def _build_explanation(frame: pd.DataFrame) -> List[str]:
    if frame.empty:
        return ["No syscalls captured. The command may have failed before execution."]

    steps: List[str] = []
    if (frame["syscall"] == "execve").any():
        steps.append("Program started via execve.")
    if frame["syscall"].isin(["openat", "mmap"]).any():
        steps.append("Loaded shared libraries and required files.")
    if (frame["syscall"] == "getdents64").any():
        steps.append("Read current directory entries.")
    if ((frame["syscall"] == "write") & frame["args"].str.startswith("1,")).any():
        steps.append("Wrote output to stdout.")
    if frame["syscall"].isin(["socket", "connect", "sendto", "recvfrom"]).any():
        steps.append("Performed network activity.")
    if not steps:
        steps.append("Command performed low-level system calls without a recognized high-level pattern.")
    return steps


def analyze_events(events: List[SyscallEvent]) -> AnalysisResult:
    frame = pd.DataFrame(events_to_rows(events))
    if frame.empty:
        frame = pd.DataFrame(columns=["pid", "timestamp", "syscall", "args", "return_value", "duration", "error", "raw"])

    if not frame.empty:
        frame["category"] = [categorize_syscall(row.syscall, row.args) for row in frame.itertuples()]
    else:
        frame["category"] = pd.Series(dtype="object")

    syscall_counts = frame["syscall"].value_counts() if not frame.empty else pd.Series(dtype="int64")
    category_counts = frame["category"].value_counts() if not frame.empty else pd.Series(dtype="int64")
    failures = int(frame["error"].notna().sum()) if not frame.empty else 0

    most_frequent = syscall_counts.index[0] if not syscall_counts.empty else "N/A"
    slowest_row = frame.loc[frame["duration"].idxmax()] if not frame.empty else None
    slowest_syscall = (
        f"{slowest_row['syscall']} ({slowest_row['duration']:.6f}s)" if slowest_row is not None else "N/A"
    )

    timeline = frame[["timestamp", "duration", "syscall"]].copy() if not frame.empty else pd.DataFrame(columns=["timestamp", "duration", "syscall"])

    summary = {
        "total_syscalls": str(len(frame.index)),
        "most_frequent": str(most_frequent),
        "slowest": str(slowest_syscall),
        "failures": str(failures),
    }

    return AnalysisResult(
        frame=frame,
        summary=summary,
        syscall_counts=syscall_counts,
        category_counts=category_counts,
        timeline=timeline,
        explanation_steps=_build_explanation(frame),
    )


def render_graphs(result: AnalysisResult, output_dir: Path) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, Path] = {}

    if not result.syscall_counts.empty:
        plt.figure(figsize=(8, 4))
        top = result.syscall_counts.head(12)
        top.plot(kind="bar", color="#4e79a7")
        plt.title("Syscall Frequency")
        plt.xlabel("Syscall")
        plt.ylabel("Count")
        plt.tight_layout()
        path = output_dir / "syscall_frequency.png"
        plt.savefig(path)
        plt.close()
        files["frequency"] = path

    if not result.timeline.empty:
        plt.figure(figsize=(8, 3.5))
        plt.plot(range(len(result.timeline.index)), result.timeline["duration"], color="#f28e2b", linewidth=1)
        plt.title("Syscall Duration Timeline")
        plt.xlabel("Event Index")
        plt.ylabel("Duration (s)")
        plt.tight_layout()
        path = output_dir / "timeline.png"
        plt.savefig(path)
        plt.close()
        files["timeline"] = path

    if not result.category_counts.empty:
        plt.figure(figsize=(6, 4))
        result.category_counts.plot(kind="bar", color="#59a14f")
        plt.title("Category Distribution")
        plt.xlabel("Category")
        plt.ylabel("Count")
        plt.tight_layout()
        path = output_dir / "categories.png"
        plt.savefig(path)
        plt.close()
        files["categories"] = path

    return files
