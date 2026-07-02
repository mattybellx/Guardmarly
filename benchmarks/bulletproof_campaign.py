#!/usr/bin/env python3
"""
BULLETPROOF 50-repo campaign — guaranteed completion with failover.
- Per-repo subprocess isolation (hang can't block other repos)
- Auto-skip test/vendor dirs (Windows-path-safe)
- File size cap at 128KB to avoid regex hangs
- 90s per-repo overall timeout
- Spare repos to replace failures → guarantees 50 results
"""
import json, os, re, shutil, subprocess, sys, time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

OUT = Path("campaign/bulletproof")
OUT.mkdir(parents=True, exist_ok=True)
REPOS_DIR = OUT / "repos"
REPOS_DIR.mkdir(exist_ok=True)

# ── Repos: 50 primary + 10 spares ──────────────────────────────────
PRIMARY_REPOS = [
    # Python (10)
    ("py-rich", "Textualize/rich", "python"),
    ("py-fastapi", "fastapi/fastapi", "python"),
    ("py-django", "django/django", "python"),
    ("py-flask", "pallets/flask", "python"),
    ("py-starlette", "encode/starlette", "python"),
    ("py-celery", "celery/celery", "python"),
    ("py-sqlalchemy", "sqlalchemy/sqlalchemy", "python"),
    ("py-tornado", "tornadoweb/tornado", "python"),
    ("py-sanic", "sanic-org/sanic", "python"),
    ("py-bottle", "bottlepy/bottle", "python"),
    # JavaScript/TypeScript (10)
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

SPARE_REPOS = [
    ("spare-py-httpx", "encode/httpx", "python"),
    ("spare-py-aiohttp", "aio-libs/aiohttp", "python"),
    ("spare-py-requests", "psf/requests", "python"),
    ("spare-js-vue", "vuejs/vue", "javascript"),
    ("spare-js-react", "facebook/react", "javascript"),
    ("spare-java-elasticsearch", "elastic/elasticsearch", "java"),
    ("spare-java-jenkins", "jenkinsci/jenkins", "java"),
    ("spare-go-prometheus", "prometheus/prometheus", "go"),
    ("spare-go-kit", "go-kit/kit", "go"),
    ("spare-cs-cleanarchitecture", "ardalis/CleanArchitecture", "csharp"),
]

# ── Semgrep-style patterns ──────────────────────────────────────────
SG_PATTERNS = [
    ("CWE-95",None,re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|\bnew\s+Function\s*\(",re.I)),
    ("CWE-78",None,re.compile(r"shell\s*=\s*True|child_process\.exec\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\([^\n]*shell\s*=\s*True",re.I)),
    ("CWE-89",None,re.compile(r"SELECT\s+.+(?:\+|\$\{|%s)|execute\s*\(\s*f[\"']|(?:cursor|db)\.execute\s*\([^\n]*(?:\+|%|format\()",re.I)),
    ("CWE-79","javascript",re.compile(r"innerHTML\s*=|document\.write\s*\(",re.I)),
    ("CWE-22",None,re.compile(r"os\.path\.join\s*\(|\bopen\s*\([^\n]*(?:request\.|req\.|filename|path)|fs\.(?:readFile|writeFile|open)\s*\([^\n]*(?:req\.|request\.)",re.I)),
    ("CWE-918",None,re.compile(r"requests\.(?:get|post|put|delete|request)\s*\(\s*\w+|fetch\s*\(\s*\w+|axios\.(?:get|post|put|delete)\s*\(\s*\w+",re.I)),
    ("CWE-601",None,re.compile(r"(?:res\.)?redirect\s*\(\s*(?:req\.|request\.|\w+\s*\?)",re.I)),
    ("CWE-502",None,re.compile(r"pickle\.(?:load|loads|dump)|ObjectInputStream|BinaryFormatter|yaml\.load\s*\(",re.I)),
    ("CWE-798",None,re.compile(r"(?:password|secret|api_key|token)\s*=\s*[\"'][^\"']{8,}[\"']",re.I)),
    ("CWE-1333","javascript",re.compile(r"/(?:[^/\\]|\\.)*(?:\([^)]*[+*][^)]*\)|\[[^\]]+\][+*])(?:[^/\\]|\\.)*[+*](?:[^/\\]|\\.)*/",re.I)),
    ("CWE-611",None,re.compile(r"DocumentBuilderFactory|XMLInputFactory|SAXParser|etree\.parse|xml\.etree",re.I)),
    ("CWE-352",None,re.compile(r"csrf\s*=\s*False|csrf_exempt|\.csrf\(\).disable\(\)|@csrf_exempt",re.I)),
]

EXT_MAP = {"python":[".py",".pyi"],"javascript":[".js",".jsx",".ts",".tsx",".mjs"],"java":[".java"],"go":[".go"],"csharp":[".cs"]}
SKIP_DIRS = {"node_modules","vendor",".git","dist","build","__pycache__",".next",".nuxt","target","bin","obj","coverage",".venv","tests","test","__tests__","spec","fixtures","examples","site-packages",".tox","eggs",".eggs","docs","doc","samples","demo"}
MAX_FILE_KB = 128
MAX_FILES = 200
REPO_TIMEOUT = 90

def clone(repo_full, dest):
    if dest.exists(): shutil.rmtree(dest)
    r = subprocess.run(["git","clone","--depth","1","--single-branch",
        f"https://github.com/{repo_full}", str(dest)],
        capture_output=True, text=True, timeout=120)
    return r.returncode == 0

def scan_repo(name, repo_full, lang):
    """Scan a single repo in a subprocess (isolation). Returns dict or None."""
    repo_dir = REPOS_DIR / name

    # Clone if needed
    if not repo_dir.exists() or not list(repo_dir.glob("*")):
        print(f"  Cloning {repo_full}...")
        if not clone(repo_full, repo_dir):
            return {"status": "clone_failed"}

    # Build config for worker
    worker_config = {
        "repo_dir": str(repo_dir),
        "lang": lang,
        "skip_dirs": list(SKIP_DIRS),
        "max_file_kb": MAX_FILE_KB,
        "max_files": MAX_FILES,
        "sg_patterns": [(c, l, p.pattern) for c, l, p in SG_PATTERNS],
        "ext_map": EXT_MAP,
        "project_src": str(Path(__file__).resolve().parent.parent / "src"),
    }
    worker_script = Path(__file__).resolve().parent / "campaign_worker.py"

    try:
        r = subprocess.run(
            [sys.executable, str(worker_script), json.dumps(worker_config)],
            capture_output=True, text=True, timeout=REPO_TIMEOUT,
            cwd=str(Path(__file__).parent),
        )
        if r.returncode != 0:
            return {"status": "error", "stderr": r.stderr[:300]}
        # Parse the last JSON line
        output = r.stdout.strip()
        return json.loads(output.split("\n")[-1] if "\n" in output else output)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except Exception as e:
        return {"status": "error", "stderr": str(e)[:300]}


# ── Main ───────────────────────────────────────────────────────────
print("=" * 60)
print("BULLETPROOF 50-REPO CAMPAIGN")
print(f"Start: {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
print(f"Per-repo timeout: {REPO_TIMEOUT}s | File cap: {MAX_FILES} | Size cap: {MAX_FILE_KB}KB")
print("=" * 60)

all_repos = list(PRIMARY_REPOS)  # 50
spares = list(SPARE_REPOS)       # 10
results = []
failed = []
spare_idx = 0

for i, (name, repo_full, lang) in enumerate(all_repos):
    print(f"\n[{i+1}/50] {name} ({lang})")

    data = scan_repo(name, repo_full, lang)
    status = data.get("status", "unknown") if data else "none"

    if status == "ok":
        r = {"name": name, "lang": lang, "loc": data["loc"], "files": data["files"],
             "ansede_n": data["ansede_n"], "ansede_tp": data["ansede_tp"], "ansede_fp": data["ansede_fp"],
             "ansede_t": data["ansede_t"], "sg_n": data["sg_n"], "sg_t": data["sg_t"]}
        results.append(r)
        print(f"  LOC={data['loc']:,} | Ansede={data['ansede_n']} ({data['ansede_t']}s) TP={data['ansede_tp']} FP={data['ansede_fp']} | Semgrep={data['sg_n']}")

        # Save incrementally
        summary = {"ts": datetime.now(timezone.utc).isoformat(), "completed": len(results),
                   "failed": len(failed), "results": results, "failures": failed}
        json.dump(summary, (OUT/"results.json").open("w"), indent=2)

    else:
        print(f"  FAILED: {status}")
        failed.append({"name": name, "repo": repo_full, "lang": lang, "status": status, "detail": data})

        # Replace with spare
        if spares and spare_idx < len(spares):
            spare_name, spare_full, spare_lang = spares[spare_idx]
            spare_idx += 1
            print(f"  → Replacing with spare: {spare_name} ({spare_lang})")
            spare_data = scan_repo(spare_name, spare_full, spare_lang)
            spare_status = spare_data.get("status", "unknown") if spare_data else "none"

            if spare_status == "ok":
                r = {"name": spare_name, "lang": spare_lang, "loc": spare_data["loc"], "files": spare_data["files"],
                     "ansede_n": spare_data["ansede_n"], "ansede_tp": spare_data["ansede_tp"], "ansede_fp": spare_data["ansede_fp"],
                     "ansede_t": spare_data["ansede_t"], "sg_n": spare_data["sg_n"], "sg_t": spare_data["sg_t"],
                     "replacement_for": name}
                results.append(r)
                print(f"  ✓ Spare OK: LOC={spare_data['loc']:,} | Ansede={spare_data['ansede_n']} TP={spare_data['ansede_tp']} FP={spare_data['ansede_fp']}")
            else:
                print(f"  ✗ Spare also failed: {spare_status}")
                failed.append({"name": spare_name, "repo": spare_full, "lang": spare_lang, "status": spare_status})
        else:
            print(f"  ✗ No spares remaining")

# ── Final Report ────────────────────────────────────────────────────
if results:
    total_loc = sum(r["loc"] for r in results)
    total_ans = sum(r["ansede_n"] for r in results)
    total_sg = sum(r["sg_n"] for r in results)
    total_tp = sum(r["ansede_tp"] for r in results)
    total_fp = sum(r["ansede_fp"] for r in results)
    prec = round(total_tp/(total_tp+total_fp)*100,1) if (total_tp+total_fp) else 0

    print("\n" + "=" * 60)
    print(f"FINAL RESULTS — {len(results)} repos completed, {len(failed)} failed")
    print("=" * 60)
    print(f"Total LOC: {total_loc:,}")
    print(f"Ansede: {total_ans} findings | TP={total_tp} FP={total_fp} | Precision={prec}%")
    print(f"Semgrep-style: {total_sg} matches")
    print(f"Ratio: {total_ans/total_sg:.1f}x" if total_sg else "")

    # Per-language
    for lang in ["python","javascript","java","go","csharp"]:
        lr = [r for r in results if r["lang"]==lang]
        if not lr: continue
        la = sum(r["ansede_n"] for r in lr)
        ls = sum(r["sg_n"] for r in lr)
        lt = sum(r["ansede_tp"] for r in lr)
        lf = sum(r["ansede_fp"] for r in lr)
        lp = round(lt/(lt+lf)*100,1) if (lt+lf) else 0
        print(f"  {lang:>12}: {len(lr):>2} repos | Ansede={la:>5} Semgrep={ls:>5} | Prec={lp}%")

    # Per-repo table
    print(f"\n{'Repo':<25} {'LOC':>8} {'Ansede':>7} {'Semgrep':>8} {'TP':>5} {'FP':>5}")
    print("-" * 65)
    for r in sorted(results, key=lambda x: x["loc"], reverse=True):
        print(f"{r['name']:<25} {r['loc']:>8,} {r['ansede_n']:>7} {r['sg_n']:>8} {r['ansede_tp']:>5} {r['ansede_fp']:>5}")

    # Save final
    final = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "completed": len(results), "failed": len(failed),
        "total_loc": total_loc, "total_files": sum(r["files"] for r in results),
        "ansede_total": total_ans, "semgrep_total": total_sg,
        "ansede_tp": total_tp, "ansede_fp": total_fp, "precision": prec,
        "ratio": round(total_ans/total_sg,1) if total_sg else 0,
        "results": results, "failures": failed,
    }
    json.dump(final, (OUT/"results.json").open("w"), indent=2)
    print(f"\nSaved: {OUT/'results.json'}")

    if len(failed) > 0:
        print(f"\nFailures ({len(failed)}):")
        for f in failed:
            print(f"  {f['name']}: {f['status']}")

print("\nDONE.")
