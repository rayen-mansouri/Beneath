# beneath

`beneath` is a Linux CLI security introspection utility that wraps `strace`, parses syscalls, and presents an interactive terminal UI.

## Features

- Run commands under `strace -f -tt -T`
- Parse syscall timestamp, name, arguments, return, duration, and errors
- Categorize calls by behavior (filesystem, process, memory, network, privilege, terminal I/O)
- Detect suspicious patterns and severity levels
- Interactive Rich TUI with summary, graphs, explanation, and alerts
- Compare two commands: `beneath --compare ls whoami`
- Export HTML report: `beneath ls --export report.html`

## Install

```bash
pip install -e .
```

## Usage

```bash
beneath ls
beneath sudo su
beneath --compare ls whoami
beneath ls --export report.html
```

## Notes

- Linux only (`strace` required).
- `strace` output is read from stderr.
- Key bindings in TUI:
  - `g`: toggle graphs
  - `e`: expand explanation
  - `s`: show only suspicious calls
  - `q`: quit
