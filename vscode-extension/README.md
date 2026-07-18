# Guardmarly for VS Code

<p align="center">
  <img src="https://raw.githubusercontent.com/mattybellx/Guardmarly/main/showcase.png" width="800" alt="Guardmarly catching CWE-22 path traversal in VS Code">
</p>

**Zero-dependency SAST scanner inline in your editor.** Catches IDOR, SQL injection, XSS, path traversal, and 30+ more CWE types as you code — fully offline, no API keys.

![1183 tests passing](https://img.shields.io/badge/1183_tests-passing-22c55e)

## Features

- 🔍 **Real-time scanning** — findings appear inline as you type
- 🛡️ **IDOR detection** — catches authorization bugs other tools miss
- 📊 **Trace-backed findings** — see the full taint path from source to sink
- 🌐 **5 languages** — Python, JavaScript/TypeScript, Go, Java, C#
- 📋 **SARIF output** — one-click export for GitHub Code Scanning
- 🔒 **100% offline** — no cloud, no API keys, no telemetry
- ⚡ **Auto-detects** guardmarly CLI — works with pip, pipx, or python -m

## Installation

Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=guardmarly.guardmarly) or:

```bash
code --install-extension guardmarly.guardmarly
```

## Usage

1. Open any Python, JavaScript, Go, Java, or C# file
2. Guardmarly scans automatically on open and on save
3. Findings appear as inline diagnostics with severity badges
4. Run `Guardmarly: Scan workspace` from the command palette for a full scan

## Settings

| Setting | Default | Description |
|---|---|---|
| `guardmarly.enabled` | `true` | Enable/disable scanning |
| `guardmarly.failOn` | `"high"` | Minimum severity to highlight |

## Commands

| Command | Description |
|---|---|
| `Guardmarly: Scan file` | Scan the active file |
| `Guardmarly: Scan workspace` | Scan all files in the workspace |

---

**100% CVE recall · Zero false positives on clean code · MIT Licensed**
