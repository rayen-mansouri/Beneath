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

## Requirements

- Linux (or WSL) with `strace`
- Python 3.10+

Install `strace`:

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install -y strace

# Fedora
sudo dnf install -y strace

# Arch
sudo pacman -S strace
```

## Install (recommended: virtual environment)

After cloning:

```bash
git clone https://github.com/rayen-mansouri/Beneath.git
cd Beneath
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

## If you get `externally-managed-environment` (PEP 668)

Many Linux distros block global `pip install` into the system Python. Use one of these:

### Option A (best): use a venv

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Option B: use `pipx`

```bash
sudo apt install -y pipx   # Debian/Ubuntu
pipx ensurepath
pipx install .
```

### Option C (not recommended): force system install

```bash
pip install -e . --break-system-packages
```

Use Option C only if you understand the risks.

## Usage

```bash
beneath ls
beneath sudo su
beneath --compare ls whoami
beneath ls --export report.html
```

## CLI Preview

Example of compare mode:

```text
$ beneath --compare ls ps
                        beneath --compare
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric          ┃ ls                 ┃ ps                     ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Total syscalls  │ 161                │ 724                    │
├─────────────────┼────────────────────┼────────────────────────┤
│ Most frequent   │ openat             │ openat                 │
├─────────────────┼────────────────────┼────────────────────────┤
│ Slowest         │ execve (0.005227s) │ getdents64 (0.017927s) │
├─────────────────┼────────────────────┼────────────────────────┤
│ Failures        │ 22                 │ 113                    │
├─────────────────┼────────────────────┼────────────────────────┤
│ Security alerts │ 0                  │ 0                      │
└─────────────────┴────────────────────┴────────────────────────┘
```

## Notes

- Linux only (`strace` required).
- On Windows, run in WSL (Ubuntu recommended).
- `strace` output is read from stderr.
- Key bindings in TUI:
  - `g`: toggle graphs
  - `e`: expand explanation
  - `s`: show only suspicious calls
  - `q`: quit
