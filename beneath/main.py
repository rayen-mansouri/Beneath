from __future__ import annotations

import argparse
import base64
import html
import os
import tempfile
from pathlib import Path
from typing import List, Sequence

import pandas as pd
from rich.console import Console
from rich.table import Table

from .analyzer import AnalysisResult, analyze_events, render_graphs
from .parser import parse_strace
from .security import detect_security_alerts
from .tracer import TraceError, run_strace
from .ui import launch_tui


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="beneath", description="Trace and explain Linux command behavior via strace.")
    parser.add_argument("command", nargs="*", help="Command to run, e.g. ls or sudo su")
    parser.add_argument("--export", dest="export_path", help="Export HTML report to path")
    parser.add_argument("--compare", nargs=2, metavar=("CMD1", "CMD2"), help="Compare two commands")
    return parser


def _split_command(command: Sequence[str]) -> List[str]:
    return [part for token in command for part in token.split()]


def _run_pipeline(command: List[str]) -> tuple[AnalysisResult, dict, list]:
    trace = run_strace(command)
    events = parse_strace(trace.stderr)
    analysis = analyze_events(events)
    alerts = detect_security_alerts(analysis.frame)

    graph_dir = Path(tempfile.mkdtemp(prefix="beneath_graphs_"))
    graph_paths = render_graphs(analysis, graph_dir)
    return analysis, graph_paths, alerts


def _encode_image(path: Path) -> str:
    raw = path.read_bytes()
    b64 = base64.b64encode(raw).decode("ascii")
    return f"data:image/png;base64,{b64}"


def export_html(path: Path, command: List[str], analysis: AnalysisResult, alerts, graph_paths) -> None:
    rows = []
    for alert in alerts:
        rows.append(f"<tr><td>{html.escape(alert.severity)}</td><td>{html.escape(alert.title)}</td><td>{html.escape(alert.syscall)}</td></tr>")

    images = []
    for label, file_path in graph_paths.items():
        images.append(
            f"<h3>{html.escape(label.title())}</h3><img src=\"{_encode_image(file_path)}\" style=\"max-width:900px;width:100%;\"/>"
        )

    doc = f"""
<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>beneath report</title>
  <style>
    body {{ font-family: Inter, Segoe UI, Arial, sans-serif; margin: 24px; background: #0b1020; color: #e6edf3; }}
    .card {{ background: #11172b; border: 1px solid #27314d; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border-bottom: 1px solid #27314d; padding: 8px; text-align: left; }}
    .sev-CRITICAL {{ color: #ff6b6b; font-weight: 700; }}
    .sev-HIGH {{ color: #ffa94d; font-weight: 700; }}
    .sev-MEDIUM {{ color: #ffd43b; font-weight: 700; }}
    .sev-LOW {{ color: #66d9e8; font-weight: 700; }}
  </style>
</head>
<body>
  <h1>beneath report</h1>
  <p><strong>Command:</strong> {html.escape(' '.join(command))}</p>

  <div class=\"card\">
    <h2>Summary</h2>
    <ul>
      <li>Total syscalls: {html.escape(analysis.summary['total_syscalls'])}</li>
      <li>Most frequent syscall: {html.escape(analysis.summary['most_frequent'])}</li>
      <li>Slowest syscall: {html.escape(analysis.summary['slowest'])}</li>
      <li>Failures: {html.escape(analysis.summary['failures'])}</li>
    </ul>
  </div>

  <div class=\"card\">
    <h2>Explanation</h2>
    <ol>{''.join(f'<li>{html.escape(step)}</li>' for step in analysis.explanation_steps)}</ol>
  </div>

  <div class=\"card\">
    <h2>Security Alerts</h2>
    <table>
      <thead><tr><th>Severity</th><th>Alert</th><th>Syscall</th></tr></thead>
      <tbody>{''.join(rows) if rows else '<tr><td colspan="3">No alerts</td></tr>'}</tbody>
    </table>
  </div>

  <div class=\"card\">
    <h2>Graphs</h2>
    {''.join(images) if images else '<p>No graph data generated.</p>'}
  </div>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8")


def run_compare(cmd1: str, cmd2: str) -> int:
    console = Console()

    analysis_1, _, alerts_1 = _run_pipeline(cmd1.split())
    analysis_2, _, alerts_2 = _run_pipeline(cmd2.split())

    table = Table(title="beneath --compare", show_lines=True)
    table.add_column("Metric")
    table.add_column(cmd1)
    table.add_column(cmd2)

    table.add_row("Total syscalls", analysis_1.summary["total_syscalls"], analysis_2.summary["total_syscalls"])
    table.add_row("Most frequent", analysis_1.summary["most_frequent"], analysis_2.summary["most_frequent"])
    table.add_row("Slowest", analysis_1.summary["slowest"], analysis_2.summary["slowest"])
    table.add_row("Failures", analysis_1.summary["failures"], analysis_2.summary["failures"])
    table.add_row("Security alerts", str(len(alerts_1)), str(len(alerts_2)))

    console.print(table)
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if os.name != "posix":
        print("beneath requires Linux/posix environment with strace.")
        return 1

    try:
        if args.compare:
            return run_compare(args.compare[0], args.compare[1])

        command = _split_command(args.command)
        if not command:
            parser.error("Provide a command to trace. Example: beneath ls")

        analysis, graph_paths, alerts = _run_pipeline(command)

        if args.export_path:
            export_html(Path(args.export_path), command, analysis, alerts, graph_paths)
            print(f"Report exported to {args.export_path}")

        launch_tui(analysis, alerts, graph_paths)
        return 0
    except TraceError as exc:
        print(f"Trace error: {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
