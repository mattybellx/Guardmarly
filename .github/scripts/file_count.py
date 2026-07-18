#!/usr/bin/env python3
"""Count supported source files for deep-wild validation report."""
from pathlib import Path
root = Path(__file__).resolve().parent.parent
exts = frozenset({'.py', '.pyi', '.js', '.ts', '.jsx', '.tsx',
                   '.go', '.java', '.cs', '.rb', '.php', '.rake'})
count = 0
for sub in ['src', 'tests']:
    d = root / sub
    if d.is_dir():
        count += sum(1 for f in d.rglob('*') if f.is_file() and f.suffix.lower() in exts)
print(f"Total supported source files: {count:,}")
print(f"10k threshold needs {max(0, 10000 - count):,} more files")
print(f"Threshold met: {count >= 10000}")
