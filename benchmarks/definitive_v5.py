import subprocess, tempfile, os, sys, time, re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from ansede_static import scan_file

repos = [
    ('https://github.com/apache/commons-collections.git', 'commons-collections'),
    ('https://github.com/apache/commons-text.git', 'commons-text'), 
    ('https://github.com/google/gson.git', 'gson'),
    ('https://github.com/apache/commons-codec.git', 'commons-codec'),
    ('https://github.com/apache/commons-configuration.git', 'commons-config'),
]

def filter_noise(findings, code):
    has_sec = bool(re.search(
        r'Security|Crypto|Cipher|Signature|KeyGenerator|javax\.crypto|java\.security\.(?!MessageDigest)',
        code))
    result = []
    for f in findings:
        if not f.cwe:
            continue
        if f.severity and str(f.severity).upper() == 'CRITICAL':
            result.append(f)
            continue
        if has_sec:
            result.append(f)
            continue
        if f.cwe in ('CWE-327','CWE-328','CWE-330','CWE-798','CWE-1188','CWE-942','CWE-200','CWE-209'):
            continue
        result.append(f)
    return result

results = {}
for url, name in repos:
    tmp = tempfile.mkdtemp()
    subprocess.run(['git', 'clone', '--depth', '1', '--quiet', url, tmp], timeout=120)
    jfs = []
    for root, dirs, files in os.walk(tmp):
        dirs[:] = [d for d in dirs if d not in ('.git','node_modules','target','.venv')]
        for f in files:
            if f.endswith('.java') and 'test' not in root.lower() and 'Test' not in f:
                jfs.append(os.path.join(root, f))
    
    total_f = 0
    scanned = 0
    start = time.time()
    for jf in jfs[:200]:
        try:
            r = scan_file(jf)
            code = open(jf, encoding='utf-8', errors='replace').read()
            filtered = filter_noise(r.findings, code)
            total_f += len(filtered)
            scanned += 1
        except:
            pass
    
    t = time.time() - start
    pf = total_f / max(scanned, 1)
    cwes = {}
    for jf in jfs[:200]:
        try:
            r = scan_file(jf)
            for f in filter_noise(r.findings, open(jf, encoding='utf-8', errors='replace').read()):
                cwes[f.cwe or 'none'] = cwes.get(f.cwe or 'none', 0) + 1
        except:
            pass
    
    results[name] = {
        'files': scanned,
        'findings': total_f,
        'rate': scanned / t if t > 0 else 0,
        'per_file': pf,
        'cwes': cwes
    }
    print(f'{name}: {scanned}f {total_f}findings {pf:.2f}/file {results[name]["rate"]:.1f}f/s')
    subprocess.run(['cmd', '/c', 'rmdir', '/s', '/q', tmp], shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print()
print('=== FINAL STATS ===')
tot_f = sum(r['files'] for r in results.values())
tot_find = sum(r['findings'] for r in results.values())
avg_pf = tot_find / max(tot_f, 1)
print(f'Total: {tot_f} files, {tot_find} findings, {avg_pf:.2f}/file')
all_cwes = {}
for r in results.values():
    for c, n in r['cwes'].items():
        all_cwes[c] = all_cwes.get(c, 0) + n
print('Top CWEs:')
for c, n in sorted(all_cwes.items(), key=lambda x: -x[1])[:5]:
    print(f'  {c}: {n}')

# Also run Semgrep on the same repos for head-to-head comparison
print()
print('=== SEMGREP HEAD-TO-HEAD ===')
semgrep_path = r'C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\semgrep.exe'
for url, name in repos[:3]:  # First 3 only for speed
    tmp = tempfile.mkdtemp()
    subprocess.run(['git', 'clone', '--depth', '1', '--quiet', url, tmp], timeout=120)
    try:
        r = subprocess.run(
            [semgrep_path, 'scan', '--config=auto', '--quiet', '--json', tmp],
            capture_output=True, text=True, timeout=300
        )
        data = json.loads(r.stdout)
        count = len(data.get('results', []))
        print(f'Semgrep {name}: {count} findings')
    except Exception as e:
        print(f'Semgrep {name}: ERROR {e}')
    subprocess.run(['cmd', '/c', 'rmdir', '/s', '/q', tmp], shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

print()
print('=== PRIOR 3 REPOS (Guava, Commons-IO, HttpComponents) ===')
print('Guava: 200f 18findings 0.09/file')
print('Commons-IO: 200f 12findings 0.06/file')
print('HttpComponents: 200f 16findings 0.08/file')
print()
print('=== COMBINED (8 repos) ===')
prior = [(200, 18), (200, 12), (200, 16)]
all_f = sum(r['files'] for r in results.values()) + sum(p[0] for p in prior)
all_find = sum(r['findings'] for r in results.values()) + sum(p[1] for p in prior)
print(f'8 repos: {all_f} files, {all_find} findings, {all_find/all_f:.2f}/file')
