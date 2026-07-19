# Guardmarly for VS Code

<p align="center">
  <img src="https://raw.githubusercontent.com/mattybellx/Guardmarly/main/showcase.png" width="800" alt="Guardmarly catching CWE-22 path traversal in VS Code">
</p>

**SAST scanner inline in your editor.** Detects IDOR, missing authorization, SQL injection, XSS, path traversal, and 30+ more CWE types — runs locally on your machine.

## Features

- 🔍 **Real-time scanning** — findings appear inline as you type
- 🛡️ **IDOR detection** — catches authorization bugs other tools miss
- 📊 **Trace-backed findings** — see the full taint path from source to sink
- 🌐 **5+ languages** — Python, JavaScript/TypeScript, Go, Java, C#, and 35+ more
- 📋 **SARIF output** — one-click export for GitHub Code Scanning
- 🔒 **Runs locally** — scans files on your machine, no cloud required
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

See [CLAIMS_AND_EVIDENCE.md](../CLAIMS_AND_EVIDENCE.md) for benchmark methodology and measured results.
