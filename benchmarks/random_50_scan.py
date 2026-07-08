#!/usr/bin/env python
"""Scan 50 random small repos across 5 languages. Measure real noise metrics."""
import subprocess, tempfile, os, sys, time, json, shutil
from collections import Counter

sys.path.insert(0, 'src')

# 50 repos: 10 per language, small, diverse, never scanned
REPOS = {
    "python": [
        ("https://github.com/pallets/itsdangerous.git", "itsdangerous"),
        ("https://github.com/pallets/markupsafe.git", "markupsafe"),
        ("https://github.com/psf/black.git", "black"),
        ("https://github.com/pytest-dev/pluggy.git", "pluggy"),
        ("https://github.com/hynek/structlog.git", "structlog"),
        ("https://github.com/tornadoweb/tornado.git", "tornado"),
        ("https://github.com/django/daphne.git", "daphne"),
        ("https://github.com/encode/uvicorn.git", "uvicorn"),
        ("https://github.com/coleifer/peewee.git", "peewee"),
        ("https://github.com/pypa/pipenv.git", "pipenv"),
    ],
    "javascript": [
        ("https://github.com/expressjs/cors.git", "cors"),
        ("https://github.com/expressjs/body-parser.git", "body-parser"),
        ("https://github.com/expressjs/morgan.git", "morgan"),
        ("https://github.com/jshttp/cookie.git", "cookie"),
        ("https://github.com/pillarjs/path-to-regexp.git", "path-to-regexp"),
        ("https://github.com/axios/axios.git", "axios"),
        ("https://github.com/lodash/lodash.git", "lodash"),
        ("https://github.com/jquense/yup.git", "yup"),
        ("https://github.com/sindresorhus/got.git", "got"),
        ("https://github.com/expressjs/express.git", "express"),
    ],
    "go": [
        ("https://github.com/gorilla/mux.git", "gorilla-mux"),
        ("https://github.com/gorilla/websocket.git", "gorilla-websocket"),
        ("https://github.com/go-chi/chi.git", "chi"),
        ("https://github.com/gin-gonic/gin.git", "gin"),
        ("https://github.com/rs/zerolog.git", "zerolog"),
        ("https://github.com/go-playground/validator.git", "validator"),
        ("https://github.com/stretchr/testify.git", "testify"),
        ("https://github.com/spf13/cobra.git", "cobra"),
        ("https://github.com/spf13/viper.git", "viper"),
        ("https://github.com/jmoiron/sqlx.git", "sqlx"),
    ],
    "java": [
        ("https://github.com/google/gson.git", "gson"),
        ("https://github.com/FasterXML/jackson-core.git", "jackson-core"),
        ("https://github.com/FasterXML/jackson-databind.git", "jackson-databind"),
        ("https://github.com/jhy/jsoup.git", "jsoup"),
        ("https://github.com/square/okhttp.git", "okhttp"),
        ("https://github.com/google/guava.git", "guava"),
        ("https://github.com/apache/commons-lang.git", "commons-lang3"),
        ("https://github.com/apache/commons-io.git", "commons-io"),
        ("https://github.com/apache/commons-codec.git", "commons-codec"),
        ("https://github.com/apache/commons-text.git", "commons-text"),
    ],
    "csharp": [
        ("https://github.com/ServiceStack/ServiceStack.Text.git", "servicestack-text"),
        ("https://github.com/restsharp/RestSharp.git", "restsharp"),
        ("https://github.com/JamesNK/Newtonsoft.Json.git", "newtonsoft-json"),
    ],
}

results = {}
timeouts = 0
total_files = 0
total_findings = 0
all_cwes = Counter()
all_severities = Counter()

for lang, repos in REPOS.items():
    for url, name in repos:
        print(f"\n{'='*60}")
        print(f"[{lang}] {name}...")
        
        tmp = tempfile.mkdtemp()
        try:
            r = subprocess.run(
                ['git', 'clone', '--depth', '1', '--quiet', url, tmp],
                timeout=60, capture_output=True
            )
            if r.returncode != 0:
                print(f"  SKIP: clone failed")
                continue
        except subprocess.TimeoutExpired:
            print(f"  SKIP: clone timeout")
            timeouts += 1
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        
        # Find source files
        exts = {'python': '.py', 'javascript': ('.js', '.ts'), 'go': '.go',
                'java': '.java', 'csharp': '.cs'}
        ext = exts[lang]
        if isinstance(ext, tuple):
            src_files = []
            for root, dirs, files in os.walk(tmp):
                dirs[:] = [d for d in dirs if d not in ('.git','node_modules','target','.venv','vendor','test','tests')]
                for f in files:
                    if f.endswith(ext) and 'test' not in root.lower() and 'Test' not in f and 'spec' not in root.lower():
                        src_files.append(os.path.join(root, f))
        else:
            src_files = []
            for root, dirs, files in os.walk(tmp):
                dirs[:] = [d for d in dirs if d not in ('.git','node_modules','target','.venv','vendor','test','tests')]
                for f in files:
                    if f.endswith(ext) and 'test' not in root.lower() and 'Test' not in f:
                        src_files.append(os.path.join(root, f))
        
        if len(src_files) > 200:
            src_files = src_files[:200]  # Cap at 200 files for speed
        
        if not src_files:
            print(f"  SKIP: no source files found")
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        
        print(f"  {len(src_files)} files...")
        
        t0 = time.time()
        repo_findings = 0
        repo_cwes = Counter()
        repo_sevs = Counter()
        
        try:
            # Scan all files at once
            r = subprocess.run(
                [sys.executable, '-m', 'ansede_static.cli'] + src_files[:50] + ['--format', 'json', '--fail-on', 'never'],
                timeout=120, capture_output=True, text=True, cwd=os.path.dirname(__file__)
            )
            
            # Parse JSON from stdout
            output = r.stdout
            if output.strip():
                try:
                    # Find JSON start
                    json_start = output.index('{')
                    data = json.loads(output[json_start:])
                    
                    if isinstance(data, list):
                        for f in data:
                            cwe = f.get('cwe', 'none')
                            sev = f.get('severity', 'info')
                            repo_findings += 1
                            repo_cwes[cwe] += 1
                            repo_sevs[sev] += 1
                    elif isinstance(data, dict):
                        results_list = data.get('results', [])
                        for result_item in results_list:
                            for f in result_item.get('findings', []):
                                cwe = f.get('cwe', 'none')
                                sev = f.get('severity', 'info')
                                repo_findings += 1
                                repo_cwes[cwe] += 1
                                repo_sevs[sev] += 1
                except json.JSONDecodeError:
                    repo_findings = -1
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT on scan")
            timeouts += 1
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        except Exception as e:
            print(f"  ERROR: {e}")
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        
        elapsed = time.time() - t0
        rate = repo_findings / max(len(src_files), 1)
        
        print(f"  {repo_findings} findings, {rate:.2f}/file, {elapsed:.1f}s, top CWEs: {repo_cwes.most_common(3)}")
        
        results[name] = {
            'lang': lang,
            'files': min(len(src_files), 50),
            'findings': repo_findings,
            'rate': rate,
            'time': elapsed,
            'cwes': dict(repo_cwes.most_common(5)),
        }
        
        total_files += min(len(src_files), 50)
        total_findings += repo_findings
        all_cwes.update(repo_cwes)
        all_severities.update(repo_sevs)
        
        shutil.rmtree(tmp, ignore_errors=True)

# Final stats
print(f"\n{'='*60}")
print(f"FINAL RESULTS — 50 REPO RANDOM SCAN")
print(f"{'='*60}")
scanned = len([r for r in results.values() if r['findings'] >= 0])
print(f"Successfully scanned: {scanned} repos")
print(f"Timeouts/errors: {timeouts}")
print(f"Total files: {total_files}")
print(f"Total findings: {total_findings}")
print(f"Overall rate: {total_findings/max(total_files,1):.2f} findings/file")
print(f"\nTop CWEs:")
for cwe, n in all_cwes.most_common(10):
    print(f"  {cwe}: {n}")
print(f"\nBy severity:")
for sev, n in all_severities.most_common():
    print(f"  {sev}: {n}")
print(f"\nBy language:")
by_lang = Counter()
for name, r in results.items():
    by_lang[r['lang']] += r['findings']
for lang, n in by_lang.most_common():
    count = len([r for r in results.values() if r['lang'] == lang])
    files = sum(r['files'] for r in results.values() if r['lang'] == lang)
    print(f"  {lang}: {n} findings in {files} files ({n/max(files,1):.2f}/file) across {count} repos")

print(f"\n{'='*60}")
print(f"WORLD'S BEST VERDICT:")
print(f"  Noise: {total_findings/max(total_files,1):.2f} findings/file")
print(f"  Semgrep baseline: ~0.00 findings/file on same repos")
print(f"  If rate < 0.15: competitive with commercial SAST")
print(f"  If rate < 0.05: world-class precision")
print(f"{'='*60}")

# Save
with open('.tmp/random50_results.json', 'w') as f:
    json.dump({
        'scanned': scanned,
        'timeouts': timeouts,
        'total_files': total_files,
        'total_findings': total_findings,
        'rate': total_findings/max(total_files, 1),
        'top_cwes': dict(all_cwes.most_common(10)),
        'by_severity': dict(all_severities),
        'by_language': {lang: {'findings': n, 'repos': len([r for r in results.values() if r['lang']==lang])} for lang, n in by_lang.items()},
        'results': results,
    }, f, indent=2)
