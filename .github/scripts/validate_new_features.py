#!/usr/bin/env python3
"""Quick validation of new features."""
from guardmarly._types import Finding, Severity, TraceFrame
from guardmarly.php_analyzer import analyze_php
from guardmarly.cli import build_parser

# Confidence labels
f1 = Finding(category='security', severity=Severity.HIGH, title='t', description='',
             line=1, rule_id='JS-002', cwe='CWE-79', agent='test', confidence=0.96,
             analysis_kind='syntax-ast', trace=(TraceFrame(kind='source', label='s', line=1),))
assert f1.confidence_label == 'structural'
print(f'  structural: {f1.confidence_label}')

f2 = Finding(category='security', severity=Severity.HIGH, title='t', description='',
             line=1, rule_id='PHP-001', cwe='CWE-89', agent='test', confidence=0.70,
             analysis_kind='pattern')
assert f2.confidence_label == 'heuristic'
print(f'  heuristic: {f2.confidence_label}')

d = f1.as_dict()
assert 'confidence_label' in d
print('  as_dict has confidence_label')

# PHP analyzer with superglobal in SQL call
code = '<?php\n$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);\n'
result = analyze_php(code)
assert len(result.findings) > 0, f'PHP analyzer produced no findings'
for f in result.findings:
    print(f'  PHP: {f.rule_id} {f.cwe} line={f.line} conf={f.confidence} label={f.confidence_label}')

# PHP Command injection
code2 = '<?php\nsystem("tar -czf " . $_POST["file"] . " archive.tgz");\n'
result2 = analyze_php(code2)
assert len(result2.findings) > 0
for f in result2.findings:
    print(f'  PHP cmd: {f.rule_id} {f.cwe} line={f.line}')

# CLI flags
p = build_parser()
assert p.parse_args(['--explain-cwe', 'CWE-89']).explain_cwe == 'CWE-89'
assert p.parse_args(['--engine', 'v2']).engine == 'v2'
assert p.parse_args(['--lang', 'php', '--stdin']).lang == 'php'
print('  CLI flags OK')

print('\nALL VALIDATIONS PASSED')
