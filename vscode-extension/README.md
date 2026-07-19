# Guardmarly for VS Code

Guardmarly for VS Code is a local editor integration for the Guardmarly CLI. It surfaces authorization-sensitive findings and other supported code-security results inline while you work.

## What it does

- highlights Guardmarly findings as VS Code diagnostics
- focuses attention on authorization / IDOR-style risks alongside other supported rules
- can scan the current file or workspace from the command palette
- relies on a local `guardmarly` CLI installation rather than a hosted scanning service

## Supported editor surfaces

The current extension activates for Python, JavaScript, TypeScript, React JSX/TSX, Go, Java, C#, Ruby, PHP, and Rust files. Detection depth still depends on the underlying CLI analyzer support.

## Installation

1. Install the CLI locally:

```bash
pip install guardmarly
```

2. Install the extension from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=guardmarly.guardmarly) or:

```bash
code --install-extension guardmarly.guardmarly
```

## Usage

1. Open a supported file in VS Code.
2. Let the extension invoke the local Guardmarly CLI.
3. Review findings in the editor or run `Guardmarly: Scan workspace` from the command palette.

## Limits

- The extension is only a presentation layer over the CLI; it does not guarantee complete authorization correctness.
- Findings still need review in the context of framework behavior and application business rules.
- Hosted or demo deployments are separate surfaces from this local editor workflow.

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

## License

The repository currently ships a custom / non-standard license text at `/home/runner/work/Guardmarly/Guardmarly/LICENSE`. See the repository README and remediation playbook for the current status.
