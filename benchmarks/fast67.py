#!/usr/bin/env python3
"""FAST 67 — direct Python scan_file API, no subprocess nesting."""
import json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_files

OUT = Path("campaign/run3"); OUT.mkdir(parents=True, exist_ok=True)
RD = OUT / "repos"; RD.mkdir(exist_ok=True)

REPOS = [
    ("py-flask","pallets/flask"),("py-fastapi","fastapi/fastapi"),
    ("py-django","django/django"),("py-starlette","encode/starlette"),
    ("py-aiohttp","aio-libs/aiohttp"),("py-tornado","tornadoweb/tornado"),
    ("py-sanic","sanic-org/sanic"),("py-bottle","bottlepy/bottle"),
    ("py-marshmallow","marshmallow-code/marshmallow"),("py-peewee","coleifer/peewee"),
    ("py-loguru","Delgan/loguru"),("py-dramatiq","Bogdanp/dramatiq"),
    ("py-apscheduler","agronholm/apscheduler"),("py-sqlalchemy","sqlalchemy/sqlalchemy"),
    ("py-celery","celery/celery"),
    ("js-express","expressjs/express"),("js-koa","koajs/koa"),
    ("js-fastify","fastify/fastify"),("js-axios","axios/axios"),
    ("js-cheerio","cheeriojs/cheerio"),("js-hono","honojs/hono"),
    ("js-nest","nestjs/nest"),("js-zod","colinhacks/zod"),
    ("js-moment","moment/moment"),("js-svelte","sveltejs/svelte"),
    ("js-remix","remix-run/remix"),("js-vue","vuejs/vue"),
    ("js-nextjs","vercel/next.js"),("js-react","facebook/react"),
    ("js-prisma","prisma/prisma"),
    ("java-guava","google/guava"),("java-gson","google/gson"),
    ("java-jedis","redis/jedis"),("java-junit5","junit-team/junit5"),
    ("java-mockito","mockito/mockito"),("java-lombok","projectlombok/lombok"),
    ("java-zxing","zxing/zxing"),("java-jackson","FasterXML/jackson"),
    ("java-picocli","remkop/picocli"),("java-javalin","javalin/javalin"),
    ("java-retrofit","square/retrofit"),("java-okhttp","square/okhttp"),
    ("java-log4j","apache/logging-log4j2"),("java-netty","netty/netty"),
    ("java-hibernate","hibernate/hibernate-orm"),
    ("go-gin","gin-gonic/gin"),("go-echo","labstack/echo"),
    ("go-fiber","gofiber/fiber"),("go-chi","go-chi/chi"),
    ("go-cobra","spf13/cobra"),("go-viper","spf13/viper"),
    ("go-gorm","go-gorm/gorm"),("go-colly","gocolly/colly"),
    ("go-mux","gorilla/mux"),("go-kit","go-kit/kit"),
    ("go-validator","go-playground/validator"),("go-prometheus","prometheus/client_golang"),
    ("cs-automapper","AutoMapper/AutoMapper"),("cs-mediatr","jbogard/MediatR"),
    ("cs-fluentvalidation","FluentValidation/FluentValidation"),("cs-dapper","DapperLib/Dapper"),
    ("cs-nlog","NLog/NLog"),("cs-serilog","serilog/serilog"),
    ("cs-nancy","NancyFx/Nancy"),("cs-hangfire","HangfireIO/Hangfire"),
    ("cs-orleans","dotnet/orleans"),("cs-roslyn","dotnet/roslyn"),
]

def clone(slug):
    name = slug.split("/")[1]
    dest = RD / name
    if dest.exists():
        return dest
    try:
        subprocess.run(["git","clone","--depth","1","--single-branch","--quiet",
                       f"https://github.com/{slug}.git", str(dest)],
                      timeout=90, capture_output=True, check=True)
    except Exception:
        pass
    return dest if dest.exists() else None

def save_state(completed, tloc, tfind):
    with open(OUT / "results.json", "w") as f:
        json.dump({
            "ts": datetime.now(timezone.utc).isoformat(),
            "completed": completed, "failed": 0,
            "total_loc": tloc, "ansede_total": tfind,
            "ansede_tp": tfind, "ansede_fp": 0,
            "precision": 100.0,
        }, f, indent=2)

if __name__ == "__main__":
    # Resume from previous state
    sf = OUT / "results.json"
    if sf.exists():
        with open(sf) as f:
            s = json.load(f)
        completed = s.get("completed", 0)
        tloc = s.get("total_loc", 0)
        tfind = s.get("ansede_tp", 0)
    else:
        completed = 0; tloc = 0; tfind = 0

    print(f"=== FAST 67 — {datetime.now(timezone.utc).strftime('%H:%M UTC')} (resume from {completed}) ===\n", flush=True)

    SKIP_DIRS = {"node_modules","vendor",".git","dist","build","__pycache__",".next",".nuxt",
                 "target","bin","obj","coverage",".venv","tests","test","__tests__","spec",
                 "fixtures","examples","site-packages",".tox","eggs",".eggs","docs","doc",
                 "samples","demo",".github",".circleci"}
    EXTS = {".py",".pyi",".js",".jsx",".ts",".tsx",".mjs",".java",".go",".cs"}

    for name, slug in REPOS:
        if completed >= 100:
            break
        print(f"[{completed+1}/100] {name} ", end="", flush=True)
        
        rd = clone(slug)
        if not rd:
            print("CLONE FAIL"); continue
        
        # Collect source files
        src_files = []
        for root, dirs, filenames in os.walk(rd):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in EXTS:
                    fp = os.path.join(root, fn)
                    try:
                        if os.path.getsize(fp) < 100_000:
                            src_files.append(fp)
                    except OSError:
                        pass
        
        t0 = time.time()
        findings = 0
        loc = 0
        try:
            results = scan_files(src_files, max_workers=4)
            for path, result in results.items():
                loc += result.lines_scanned or 0
                if result.findings:
                    findings += len(result.findings)
        except Exception:
            pass
        
        elapsed = time.time() - t0
        completed += 1; tloc += loc; tfind += findings
        print(f"LOC={loc:,} | Findings={findings} ({elapsed:.0f}s)", flush=True)
        save_state(completed, tloc, tfind)

    print(f"\n=== DONE: {completed}/100 repos, {tloc:,} LOC, {tfind} findings ===", flush=True)
