from __future__ import annotations

import select
import sys
import termios
import threading
import tty
import time
from pathlib import Path
from typing import Dict, List

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .analyzer import AnalysisResult
from .security import SecurityAlert


class _KeyReader:
    def __init__(self) -> None:
        self.last_key: str | None = None
        self._stop = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not sys.stdin.isatty():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not self._stop:
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    char = sys.stdin.read(1)
                    self.last_key = char.lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    def consume(self) -> str | None:
        key = self.last_key
        self.last_key = None
        return key

    def stop(self) -> None:
        self._stop = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.2)


def _severity_style(severity: str) -> str:
    return {
        "LOW": "cyan",
        "MEDIUM": "yellow",
        "HIGH": "bold red",
        "CRITICAL": "bold white on red",
    }.get(severity, "white")


def _build_summary(result: AnalysisResult) -> Panel:
    table = Table.grid(expand=True)
    table.add_column()
    table.add_column()
    table.add_row("Total syscalls", result.summary["total_syscalls"])
    table.add_row("Most frequent", result.summary["most_frequent"])
    table.add_row("Slowest", result.summary["slowest"])
    table.add_row("Failures", result.summary["failures"])
    return Panel(table, title="Summary", border_style="green")


def _mini_bar(label: str, value: int, max_value: int) -> str:
    width = 24
    filled = 0 if max_value == 0 else int((value / max_value) * width)
    return f"{label:<14} {'█' * filled}{'░' * (width - filled)} {value}"


def _build_graphs(result: AnalysisResult, graph_paths: Dict[str, Path]) -> Panel:
    lines: List[str] = []

    if not result.syscall_counts.empty:
        max_value = int(result.syscall_counts.iloc[0])
        lines.append("[bold]Syscall Frequency[/bold]")
        for name, count in result.syscall_counts.head(8).items():
            lines.append(_mini_bar(str(name), int(count), max_value))

    if not result.category_counts.empty:
        max_value = int(result.category_counts.iloc[0])
        lines.append("\n[bold]Category Distribution[/bold]")
        for name, count in result.category_counts.items():
            lines.append(_mini_bar(str(name)[:14], int(count), max_value))

    if not result.timeline.empty:
        durations = result.timeline["duration"].head(60).tolist()
        max_dur = max(durations) if durations else 1
        spark = "".join("▁▂▃▄▅▆▇█"[min(7, int((d / max_dur) * 7))] for d in durations)
        lines.append("\n[bold]Duration Timeline[/bold]")
        lines.append(spark or "(no duration data)")

    if graph_paths:
        lines.append("\n[dim]Matplotlib graph files:[/dim]")
        for key, path in graph_paths.items():
            lines.append(f"- {key}: {path}")

    body = "\n".join(lines) if lines else "No graph data available."
    return Panel(body, title="Graphs", border_style="blue")


def _build_explanation(steps: List[str], expanded: bool) -> Panel:
    shown = steps if expanded else steps[:4]
    body = "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(shown))
    if not expanded and len(steps) > 4:
        body += f"\n... {len(steps) - 4} more step(s). Press 'e' to expand."
    return Panel(body or "No explanation available.", title="Human Explanation", border_style="magenta")


def _build_alerts(alerts: List[SecurityAlert], suspicious_only: bool) -> Panel:
    if not alerts:
        return Panel("No suspicious behavior detected.", title="Security Alerts", border_style="green")

    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Alert", ratio=1)

    selected = [a for a in alerts if a.severity in {"MEDIUM", "HIGH", "CRITICAL"}] if suspicious_only else alerts
    for alert in selected[:20]:
        sev = Text(f"[{alert.severity}]", style=_severity_style(alert.severity))
        table.add_row(sev, f"{alert.title} :: {alert.syscall}")

    if len(selected) > 20:
        table.add_row("", f"... {len(selected) - 20} more alerts")

    return Panel(table, title="Security Alerts", border_style="red")


def launch_tui(result: AnalysisResult, alerts: List[SecurityAlert], graph_paths: Dict[str, Path]) -> None:
    console = Console()
    key_reader = _KeyReader()

    show_graphs = True
    expanded_explanation = False
    suspicious_only = False

    key_reader.start()
    layout = Layout()
    layout.split_column(
        Layout(name="top", ratio=1),
        Layout(name="middle", ratio=2),
        Layout(name="bottom", ratio=2),
    )
    layout["top"].split_row(Layout(name="summary"), Layout(name="explanation"))
    layout["middle"].split_row(Layout(name="graphs"), Layout(name="alerts"))

    help_line = Text("Keys: [g] graphs  [e] expand explanation  [s] suspicious only  [q] quit", style="bold cyan")

    try:
        with Live(layout, console=console, refresh_per_second=8, screen=True):
            while True:
                layout["summary"].update(_build_summary(result))
                layout["explanation"].update(_build_explanation(result.explanation_steps, expanded_explanation))
                layout["graphs"].update(_build_graphs(result, graph_paths) if show_graphs else Panel("Graphs hidden. Press 'g'.", title="Graphs"))
                layout["alerts"].update(_build_alerts(alerts, suspicious_only))
                layout["bottom"].update(Panel(Group(help_line), border_style="cyan"))

                key = key_reader.consume()
                if key == "q":
                    break
                if key == "g":
                    show_graphs = not show_graphs
                if key == "e":
                    expanded_explanation = not expanded_explanation
                if key == "s":
                    suspicious_only = not suspicious_only

                time.sleep(0.1)
    finally:
        key_reader.stop()
