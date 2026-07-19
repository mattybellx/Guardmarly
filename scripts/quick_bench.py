"""Quick benchmark scan across samples/, src/, and tests/."""
import subprocess, json, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def scan_dir(path, label, timeout=300):
    result = subprocess.run(
        [sys.executable, '-m', 'guardmarly.cli', str(path), '--format', 'json', '--all-findings'],
        capture_output=True, text=True, timeout=timeout, cwd=str(ROOT)
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {'label': label, 'error': 'json parse failed', 'stdout_preview': result.stdout[:200]}
    
    findings_count = sum(len(r.get('findings', [])) for r in data)
    files_scanned = len(data)
    
    sevs = {}
    cwes = {}
    rules = {}
    idor_count = 0
    for r in data:
        for f in r.get('findings', []):
            sev = f.get('severity', '?')
            cwe = f.get('cwe', '?')
            rule = f.get('rule_id', '?')
            sevs[sev] = sevs.get(sev, 0) + 1
            cwes[cwe] = cwes.get(cwe, 0) + 1
            rules[rule] = rules.get(rule, 0) + 1
            if cwe == 'CWE-639':
                idor_count += 1
    
    # Count LOC
    loc = 0
    for ext in ['.py', '.js', '.ts', '.java', '.cs', '.go', '.php', '.rb']:
        for f in Path(path).rglob(f'*{ext}'):
            try:
                loc += sum(1 for _ in open(f, errors='replace'))
            except OSError:
                pass
    
    return {
        'label': label,
        'findings': findings_count,
        'files': files_scanned,
        'loc': loc,
        'severity': sevs,
        'top_cwes': dict(sorted(cwes.items(), key=lambda x: -x[1])[:10]),
        'top_rules': dict(sorted(rules.items(), key=lambda x: -x[1])[:10]),
        'idor_findings': idor_count,
    }


if __name__ == '__main__':
    scans = [
        ('samples/', 'samples (vulnerable)'),
        ('tests/', 'tests'),
    ]
    
    results = []
    for path, label in scans:
        if not (ROOT / path).exists():
            print(f"SKIP {label}: path not found")
            continue
        print(f"Scanning {label}...", flush=True)
        r = scan_dir(str(ROOT / path), label)
        results.append(r)
    
    print("\n" + "=" * 60)
    print("GUARDMARLY BENCHMARK — 2026-07-19")
    print("=" * 60)
    
    total_findings = 0
    total_loc = 0
    total_idor = 0
    
    for r in results:
        print(f"\n## {r['label']}")
        if 'error' in r:
            print(f"  ERROR: {r['error']}")
            continue
        print(f"  Files: {r['files']}  |  LOC: {r['loc']:,}  |  Findings: {r['findings']}")
        print(f"  Findings/kLOC: {r['findings'] / (r['loc']/1000):.1f}" if r['loc'] > 0 else "  Findings/kLOC: N/A")
        print(f"  Severity: {r['severity']}")
        print(f"  CWE-639 IDOR: {r['idor_findings']}")
        print(f"  Top CWEs: {dict(list(r['top_cwes'].items())[:6])}")
        print(f"  Top Rules: {dict(list(r['top_rules'].items())[:6])}")
        total_findings += r['findings']
        total_loc += r['loc']
        total_idor += r['idor_findings']
    
    print(f"\n{'=' * 60}")
    print(f"TOTALS: {total_findings} findings | {total_loc:,} LOC | {total_findings / (total_loc/1000):.1f}/kLOC" if total_loc > 0 else "")
    print(f"CWE-639 IDOR: {total_idor}")
    
    # Write to benchmark file
    benchmark_path = ROOT / 'results' / 'benchmarks' / '2026-07-19-baseline.json'
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_data = {
        'version': 'baseline-2026-07-19',
        'timestamp': '2026-07-19',
        'scans': results,
        'totals': {
            'findings': total_findings,
            'loc': total_loc,
            'idor_findings': total_idor,
        }
    }
    benchmark_path.write_text(json.dumps(benchmark_data, indent=2))
    print(f"\nBaseline written to {benchmark_path}")
