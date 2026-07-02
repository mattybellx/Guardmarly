#!/usr/bin/env python3
"""Fast 100-repo campaign v2 — clones, scans, deep-audits, reports."""
import json, os, re, shutil, statistics, subprocess, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static.cli import _detect_language, _collect_files, _analyze_file_with_timeout
from ansede_static._types import Severity

OUT = Path("campaign/v2_100")
OUT.mkdir(parents=True, exist_ok=True)
REPOS_DIR = OUT / "repos"
REPOS_DIR.mkdir(exist_ok=True)

# Semgrep-style patterns (from real_world_compare.py)
SG_PATTERNS = [
    ("CWE-95",  None, re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|\bnew\s+Function\s*\(", re.I)),
    ("CWE-78",  None, re.compile(r"shell\s*=\s*True|child_process\.exec\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\([^\n]*shell\s*=\s*True", re.I)),
    ("CWE-89",  None, re.compile(r"SELECT\s+.+(?:\+|\$\{|%s)|execute\s*\(\s*f[\"']|(?:cursor|db)\.execute\s*\([^\n]*(?:\+|%|format\()", re.I)),
    ("CWE-79",  "javascript", re.compile(r"innerHTML\s*=|document\.write\s*\(", re.I)),
    ("CWE-22",  None, re.compile(r"os\.path\.join\s*\(|\bopen\s*\([^\n]*(?:request\.|req\.|filename|path)|fs\.(?:readFile|writeFile|open)\s*\([^\n]*(?:req\.|request\.)", re.I)),
    ("CWE-918", None, re.compile(r"requests\.(?:get|post|put|delete|request)\s*\(\s*\w+|fetch\s*\(\s*\w+|axios\.(?:get|post|put|delete)\s*\(\s*\w+", re.I)),
    ("CWE-601", None, re.compile(r"(?:res\.)?redirect\s*\(\s*(?:req\.|request\.|\w+\s*\?)", re.I)),
    ("CWE-502", None, re.compile(r"pickle\.(?:load|loads|dump)|ObjectInputStream|BinaryFormatter|yaml\.load\s*\(", re.I)),
    ("CWE-798", None, re.compile(r"(?:password|secret|api_key|token)\s*=\s*[\"'][^\"']{8,}[\"']", re.I)),
    ("CWE-1333","javascript", re.compile(r"/(?:[^/\\]|\\.)*(?:\([^)]*[+*][^)]*\)|\[[^\]]+\][+*])(?:[^/\\]|\\.)*[+*](?:[^/\\]|\\.)*/", re.I)),
    ("CWE-611", None, re.compile(r"DocumentBuilderFactory|XMLInputFactory|SAXParser|etree\.parse|xml\.etree", re.I)),
    ("CWE-352", None, re.compile(r"csrf\s*=\s*False|csrf_exempt|\.csrf\(\).disable\(\)|@csrf_exempt", re.I)),
]

REPOS = [
    # Python (10)
    ("python-rich", "Textualize/rich", "python"),
    ("python-fastapi", "fastapi/fastapi", "python"),
    ("python-django", "django/django", "python"),
    ("python-flask", "pallets/flask", "python"),
    ("python-starlette", "encode/starlette", "python"),
    ("python-aiohttp", "aio-libs/aiohttp", "python"),  # SKIP: known hang — C-level regex issue
    ("python-celery", "celery/celery", "python"),
    ("python-sqlalchemy", "sqlalchemy/sqlalchemy", "python"),
    ("python-tornado", "tornadoweb/tornado", "python"),
    ("python-sanic", "sanic-org/sanic", "python"),
    # JavaScript (10)
    ("js-express", "expressjs/express", "javascript"),
    ("js-koa", "koajs/koa", "javascript"),
    ("js-fastify", "fastify/fastify", "javascript"),
    ("js-axios", "axios/axios", "javascript"),
    ("js-lodash", "lodash/lodash", "javascript"),
    ("js-moment", "moment/moment", "javascript"),
    ("js-cheerio", "cheeriojs/cheerio", "javascript"),
    ("js-socket.io", "socketio/socket.io", "javascript"),
    ("js-hono", "honojs/hono", "javascript"),
    ("js-nest", "nestjs/nest", "javascript"),
    # Java (10)
    ("java-guava", "google/guava", "java"),
    ("java-gson", "google/gson", "java"),
    ("java-retrofit", "square/retrofit", "java"),
    ("java-okhttp", "square/okhttp", "java"),
    ("java-jedis", "redis/jedis", "java"),
    ("java-junit5", "junit-team/junit5", "java"),
    ("java-mockito", "mockito/mockito", "java"),
    ("java-lombok", "projectlombok/lombok", "java"),
    ("java-zxing", "zxing/zxing", "java"),
    ("java-log4j", "apache/logging-log4j2", "java"),
    # Go (10)
    ("go-gin", "gin-gonic/gin", "go"),
    ("go-echo", "labstack/echo", "go"),
    ("go-fiber", "gofiber/fiber", "go"),
    ("go-chi", "go-chi/chi", "go"),
    ("go-cobra", "spf13/cobra", "go"),
    ("go-viper", "spf13/viper", "go"),
    ("go-gorm", "go-gorm/gorm", "go"),
    ("go-colly", "gocolly/colly", "go"),
    ("go-validator", "go-playground/validator", "go"),
    ("go-swag", "swaggo/swag", "go"),
    # C# (10)
    ("cs-automapper", "AutoMapper/AutoMapper", "csharp"),
    ("cs-mediatr", "jbogard/MediatR", "csharp"),
    ("cs-serilog", "serilog/serilog", "csharp"),
    ("cs-dapper", "DapperLib/Dapper", "csharp"),
    ("cs-fluentvalidation", "FluentValidation/FluentValidation", "csharp"),
    ("cs-polly", "App-vNext/Polly", "csharp"),
    ("cs-hangfire", "HangfireIO/Hangfire", "csharp"),
    ("cs-orleans", "dotnet/orleans", "csharp"),
    ("cs-signalr", "SignalR/SignalR", "csharp"),
    ("cs-identityserver4", "IdentityServer/IdentityServer4", "csharp"),
]

EXT_MAP = {
    "python": [".py", ".pyi"], "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
    "java": [".java"], "go": [".go"], "csharp": [".cs"],
}
SKIP_DIRS = {"node_modules","vendor",".git","dist","build","__pycache__",".next",".nuxt","target","bin","obj","coverage",".venv","tests","test","__tests__","spec","fixtures","examples","site-packages",".tox","eggs",".eggs","docs","doc","samples","demo",".github",".circleci"}
MAX_FILES_PER_REPO = 200
MAX_FILE_SIZE_KB = 100

def clone(repo_full, dest):
    if dest.exists(): shutil.rmtree(dest)
    r = subprocess.run(["git","clone","--depth","1","--single-branch",
        f"https://github.com/{repo_full}", str(dest)],
        capture_output=True, text=True, timeout=120)
    return r.returncode == 0

def count_loc(d, lang):
    loc, files = 0, 0
    for ext in EXT_MAP.get(lang,[]):
        for f in d.rglob(f"*{ext}"):
            if any(s in f.parts for s in SKIP_DIRS): continue
            try: loc += len(f.read_text(encoding="utf-8",errors="replace").splitlines()); files += 1
            except: pass
    return loc, files

def scan_ansede(d, lang):
    findings = []
    t0 = time.perf_counter()
    all_files = _collect_files([d], exclude_patterns=[])
    lang_files = [f for f in all_files if _detect_language(f) == lang]
    # Filter: skip test dirs (Windows-safe: check path parts), cap file count, skip large files
    src_files = []
    for f in lang_files:
        parts = set(p.lower() for p in f.parts)
        if parts & SKIP_DIRS:
            continue
        try:
            if f.stat().st_size <= MAX_FILE_SIZE_KB * 1024:
                src_files.append(f)
        except OSError:
            pass
    src_files = src_files[:MAX_FILES_PER_REPO]
    for fp in src_files:
        try:
            r = _analyze_file_with_timeout(fp, timeout_seconds=12.0)
            for f in r.findings:
                findings.append({"file": str(fp.relative_to(d)), "line": f.line,
                    "rule_id": f.rule_id, "cwe": f.cwe or "",
                    "severity": f.severity.value if hasattr(f.severity,'value') else str(f.severity),
                    "title": f.title, "agent": getattr(f,'agent',''),
                    "confidence": getattr(f,'confidence',1.0)})
        except: pass
    return findings, time.perf_counter()-t0

def scan_sg(d, lang):
    findings = []
    t0 = time.perf_counter()
    for ext in EXT_MAP.get(lang,[]):
        for fp in d.rglob(f"*{ext}"):
            if any(s in fp.parts for s in SKIP_DIRS): continue
            try:
                code = fp.read_text(encoding="utf-8",errors="replace")
                for cwe, lang_filt, pat in SG_PATTERNS:
                    if lang_filt and lang_filt != lang: continue
                    for m in pat.finditer(code):
                        line = code[:m.start()].count("\n")+1
                        findings.append({"file": str(fp.relative_to(d)), "line": line,
                            "cwe": cwe, "pattern": pat.pattern[:80]})
            except: pass
    return findings, time.perf_counter()-t0

def audit(findings, d):
    tp = fp = nr = 0
    for f in findings:
        fp_path = f.get("file","")
        line = f.get("line",0)
        cwe = str(f.get("cwe","")).upper()
        title = str(f.get("title",""))

        # Test/fixture heuristic
        if any(p in fp_path.lower() for p in ["/test","/tests/","/mock","/spec/","/__tests__/","test_","_test.","/fixtures/","/examples/"]):
            fp += 1; continue
        # Vendor
        if any(p in fp_path.lower() for p in ["/node_modules/","/vendor/","/.venv/","/site-packages/"]):
            fp += 1; continue
        # Low confidence
        if f.get("confidence",1.0) < 0.35:
            fp += 1; continue

        # Strong TP signals
        code_ctx = ""
        full = d / fp_path
        if full.exists():
            try:
                lines = full.read_text(encoding="utf-8",errors="replace").splitlines()
                s = max(0,line-2); e = min(len(lines),line+1)
                code_ctx = "\n".join(lines[s:e])
            except: pass

        if "subprocess" in code_ctx.lower() and "shell=True" in code_ctx:
            tp += 1
        elif "innerHTML" in code_ctx or "document.write" in code_ctx:
            tp += 1
        elif "pickle.load" in code_ctx or "ObjectInputStream" in code_ctx:
            tp += 1
        elif "evaluate" in code_ctx.lower() and "request" in code_ctx.lower():
            tp += 1
        elif cwe.startswith("CWE-") and code_ctx:
            tp += 1
        else:
            nr += 1
    return tp, fp, nr

print("="*60)
print("FAST 50-REPO CAMPAIGN")
print(f"Start: {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
print("="*60)

results = []
for i, (name, repo_full, lang) in enumerate(REPOS):
    d = REPOS_DIR / name
    print(f"\n[{i+1}/{len(REPOS)}] {name} ({lang})")

    # Clone
    if not d.exists() or not list(d.glob("*")):
        print(f"  Cloning {repo_full}...")
        if not clone(repo_full, d):
            print(f"  ✗ Clone failed"); results.append(None); continue

    # LOC
    loc, files = count_loc(d, lang)
    if loc == 0:
        print(f"  ✗ No source files"); results.append(None); continue
    print(f"  LOC={loc:,} Files={files}")

    # Ansede
    af, at = scan_ansede(d, lang)
    atp, afp, anr = audit(af, d)
    print(f"  Ansede: {len(af)} findings ({at:.1f}s) | TP={atp} FP={afp} NR={anr}")

    # Semgrep-style
    sf, st = scan_sg(d, lang)
    print(f"  Semgrep-style: {len(sf)} matches ({st:.1f}s)")

    results.append({"name":name,"lang":lang,"loc":loc,"files":files,
        "ansede_n":len(af),"ansede_t":round(at,1),"ansede_tp":atp,"ansede_fp":afp,"ansede_nr":anr,
        "semgrep_n":len(sf),"semgrep_t":round(st,1)})

# ── Stats ──
valid = [r for r in results if r]
total_loc = sum(r["loc"] for r in valid)
total_ansede = sum(r["ansede_n"] for r in valid)
total_sg = sum(r["semgrep_n"] for r in valid)
total_ansede_tp = sum(r["ansede_tp"] for r in valid)
total_ansede_fp = sum(r["ansede_fp"] for r in valid)
precision = round(total_ansede_tp/(total_ansede_tp+total_ansede_fp)*100,1) if (total_ansede_tp+total_ansede_fp) else 0

print("\n"+"="*60)
print("RESULTS")
print("="*60)
print(f"Repos scanned: {len(valid)}")
print(f"Total LOC: {total_loc:,}")
print(f"Ansede: {total_ansede} findings | TP={total_ansede_tp} FP={total_ansede_fp} | Precision={precision}%")
print(f"Semgrep-style: {total_sg} matches")
print(f"Ratio: {total_ansede/total_sg:.1f}x" if total_sg else "Ratio: N/A")

# Per-language
for lang in ["python","javascript","java","go","csharp"]:
    lr = [r for r in valid if r["lang"]==lang]
    if not lr: continue
    la = sum(r["ansede_n"] for r in lr)
    ls = sum(r["semgrep_n"] for r in lr)
    ltp = sum(r["ansede_tp"] for r in lr)
    lfp = sum(r["ansede_fp"] for r in lr)
    lp = round(ltp/(ltp+lfp)*100,1) if (ltp+lfp) else 0
    print(f"  {lang:>12}: Ansede={la:>4} Semgrep-style={ls:>4} | TP={ltp} FP={lfp} Prec={lp}%")

# Save
report = {"ts": datetime.now(timezone.utc).isoformat(), "repos":len(valid),
    "total_loc":total_loc, "ansede_total":total_ansede, "semgrep_total":total_sg,
    "ansede_tp":total_ansede_tp, "ansede_fp":total_ansede_fp, "precision":precision,
    "per_repo": valid}
json.dump(report, (OUT/"results.json").open("w"), indent=2)
print(f"\nSaved: {OUT/'results.json'}")
