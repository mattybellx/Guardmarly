"""Check all Python source files for Python 3.9 syntax compatibility."""
import ast, sys
from pathlib import Path

issues = []
for f in sorted(Path('src/ansede_static').rglob('*.py')):
    if '__pycache__' in str(f):
        continue
    try:
        ast.parse(f.read_text(encoding='utf-8', errors='replace'), filename=str(f))
    except SyntaxError as e:
        issues.append((f, e))

# Also check tests
for f in sorted(Path('tests').rglob('*.py')):
    if '__pycache__' in str(f):
        continue
    try:
        ast.parse(f.read_text(encoding='utf-8', errors='replace'), filename=str(f))
    except SyntaxError as e:
        issues.append((f, e))

if not issues:
    print('All files pass Python 3.9 syntax check')
else:
    for f, e in issues:
        print('%s: %s' % (f, e))
