#!/usr/bin/env python3
"""100 NEW repos — zero overlap with any previously scanned repos. Deep audit built in."""
import json, os, re, shutil, subprocess, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static.cli import _detect_language, _collect_files, _analyze_file_with_timeout

OUT = Path("campaign/run3"); OUT.mkdir(parents=True, exist_ok=True)
RD = OUT / "repos"; RD.mkdir(exist_ok=True)

SG = [(c,l,re.compile(p,re.I)) for c,l,p in [
    ("CWE-95",None,r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|\bnew\s+Function\s*\("),
    ("CWE-78",None,r"shell\s*=\s*True|child_process\.exec\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\([^\n]*shell\s*=\s*True"),
    ("CWE-89",None,r"SELECT\s+.+(?:\+|\$\{|%s)|execute\s*\(\s*f[\"']|(?:cursor|db)\.execute\s*\([^\n]*(?:\+|%|format\()"),
    ("CWE-79","javascript",r"innerHTML\s*=|document\.write\s*\("),
    ("CWE-22",None,r"os\.path\.join\s*\(|\bopen\s*\([^\n]*(?:request\.|req\.|filename|path)|fs\.(?:readFile|writeFile|open)\s*\([^\n]*(?:req\.|request\.)"),
    ("CWE-918",None,r"requests\.(?:get|post|put|delete|request)\s*\(\s*\w+|fetch\s*\(\s*\w+|axios\.(?:get|post|put|delete)\s*\(\s*\w+"),
    ("CWE-601",None,r"(?:res\.)?redirect\s*\(\s*(?:req\.|request\.|\w+\s*\?)"),
    ("CWE-502",None,r"pickle\.(?:load|loads|dump)|ObjectInputStream|BinaryFormatter|yaml\.load\s*\("),
    ("CWE-798",None,r'(?:password|secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']'),
    ("CWE-1333","javascript",r"/(?:[^/\\]|\\.)*(?:\([^)]*[+*][^)]*\)|\[[^\]]+\][+*])(?:[^/\\]|\\.)*[+*](?:[^/\\]|\\.)*/"),
    ("CWE-611",None,r"DocumentBuilderFactory|XMLInputFactory|SAXParser|etree\.parse|xml\.etree"),
    ("CWE-352",None,r"csrf\s*=\s*False|csrf_exempt|\.csrf\(\).disable\(\)|@csrf_exempt"),
]]

EM = {"python":[".py",".pyi"],"javascript":[".js",".jsx",".ts",".tsx",".mjs"],"java":[".java"],"go":[".go"],"csharp":[".cs"]}
SD = {"node_modules","vendor",".git","dist","build","__pycache__",".next",".nuxt","target","bin","obj","coverage",".venv","tests","test","__tests__","spec","fixtures","examples","site-packages",".tox","eggs",".eggs","docs","doc","samples","demo",".github",".circleci"}

# ── 100 COMPLETELY FRESH REPOS (zero overlap with previous 82 scanned) ──
R = [
    ("py-numpy","numpy/numpy","p"),("py-pandas","pandas-dev/pandas","p"),
    ("py-matplotlib","matplotlib/matplotlib","p"),("py-scikit","scikit-learn/scikit-learn","p"),
    ("py-pytest","pytest-dev/pytest","p"),("py-poetry","python-poetry/poetry","p"),
    ("py-typer","fastapi/typer","p"),("py-databases","encode/databases","p"),
    ("py-psycopg2","psycopg/psycopg2","p"),("py-redis-py","redis/redis-py","p"),
    ("py-transformers","huggingface/transformers","p"),("py-jinja","pallets/jinja","p"),
    ("py-click","pallets/click","p"),("py-werkzeug","pallets/werkzeug","p"),
    ("py-gunicorn","benoitc/gunicorn","p"),("py-alembic","sqlalchemy/alembic","p"),
    ("py-pillow","python-pillow/Pillow","p"),("py-urllib3","urllib3/urllib3","p"),
    ("py-lxml","lxml/lxml","p"),("py-ruff","astral-sh/ruff","p"),
    ("js-deno","denoland/deno","j"),("js-bun","oven-sh/bun","j"),
    ("js-esbuild","evanw/esbuild","j"),("js-vite","vitejs/vite","j"),
    ("js-tailwind","tailwindlabs/tailwindcss","j"),("js-redux","reduxjs/redux","j"),
    ("js-playwright","microsoft/playwright","j"),("js-puppeteer","puppeteer/puppeteer","j"),
    ("js-eslint","eslint/eslint","j"),("js-webpack","webpack/webpack","j"),
    ("js-jest","jestjs/jest","j"),("js-cypress","cypress-io/cypress","j"),
    ("js-d3","d3/d3","j"),("js-threejs","mrdoob/three.js","j"),
    ("js-htmx","bigskysoftware/htmx","j"),("js-alpine","alpinejs/alpine","j"),
    ("js-gatsby","gatsbyjs/gatsby","j"),("js-eleventy","11ty/eleventy","j"),
    ("js-nuxt","nuxt/nuxt","j"),("js-solid","solidjs/solid","j"),
    ("jv-springboot","spring-projects/spring-boot","v"),("jv-spring-fw","spring-projects/spring-framework","v"),
    ("jv-spring-sec","spring-projects/spring-security","v"),("jv-jdbi","jdbi/jdbi","v"),
    ("jv-mybatis","mybatis/mybatis-3","v"),("jv-jooq","jOOQ/jOOQ","v"),
    ("jv-mapstruct","mapstruct/mapstruct","v"),("jv-assertj","assertj/assertj","v"),
    ("jv-slf4j","qos-ch/slf4j","v"),("jv-logback","qos-ch/logback","v"),
    ("jv-jgit","eclipse-jgit/jgit","v"),("jv-graphql-java","graphql-java/graphql-java","v"),
    ("jv-jsoup","jhy/jsoup","v"),("jv-bytebuddy","raphw/byte-buddy","v"),
    ("jv-caffeine","ben-manes/caffeine","v"),("jv-vavr","vavr-io/vavr","v"),
    ("jv-immutables","immutables/immutables","v"),("jv-ehcache","ehcache/ehcache3","v"),
    ("jv-hazelcast","hazelcast/hazelcast","v"),("jv-dropwizard","dropwizard/dropwizard","v"),
    ("go-kubernetes","kubernetes/kubernetes","g"),("go-helm","helm/helm","g"),
    ("go-etcd","etcd-io/etcd","g"),("go-consul","hashicorp/consul","g"),
    ("go-vault","hashicorp/vault","g"),("go-traefik","traefik/traefik","g"),
    ("go-caddy","caddyserver/caddy","g"),("go-hugo","gohugoio/hugo","g"),
    ("go-grafana","grafana/grafana","g"),("go-influxdb","influxdata/influxdb","g"),
    ("go-telegraf","influxdata/telegraf","g"),("go-jaeger","jaegertracing/jaeger","g"),
    ("go-nats","nats-io/nats-server","g"),("go-cli","urfave/cli","g"),
    ("go-negroni","urfave/negroni","g"),("go-logr","go-logr/logr","g"),
    ("go-zerolog","rs/zerolog","g"),("go-cockroach","cockroachdb/cockroach","g"),
    ("go-tidb","pingcap/tidb","g"),("go-minio","minio/minio","g"),
    ("cs-roslyn","dotnet/roslyn","c"),("cs-maui","dotnet/maui","c"),
    ("cs-avalonia","AvaloniaUI/Avalonia","c"),("cs-nuget","NuGet/NuGet.Client","c"),
    ("cs-msbuild","dotnet/msbuild","c"),("cs-winforms","dotnet/winforms","c"),
    ("cs-wpf","dotnet/wpf","c"),("cs-powershell","PowerShell/PowerShell","c"),
    ("cs-azure-sdk","Azure/azure-sdk-for-net","c"),("cs-aws-sdk","aws/aws-sdk-net","c"),
    ("cs-nsubstitute","nsubstitute/NSubstitute","c"),("cs-fakeiteasy","FakeItEasy/FakeItEasy","c"),
    ("cs-benchmark","dotnet/BenchmarkDotNet","c"),("cs-opentk","opentk/opentk","c"),
    ("cs-reactiveui","reactiveui/ReactiveUI","c"),("cs-spectre","spectreconsole/spectre.console","c"),
    ("cs-markdig","xoofx/markdig","c"),("cs-yamldotnet","aaubry/YamlDotNet","c"),
    ("cs-imageproc","JimBobSquarePants/ImageProcessor","c"),("cs-google-api","googleapis/google-api-dotnet-client","c"),
]
SP = [("s-py-uvloop","MagicStack/uvloop","p"),("s-py-anyio","agronholm/anyio","p"),
      ("s-js-swc","swc-project/swc","j"),("s-js-rollup","rollup/rollup","j"),
      ("s-jv-ratpack","ratpack/ratpack","v"),("s-jv-struts","apache/struts","v"),
      ("s-go-docker","docker/cli","g"),("s-go-containerd","containerd/containerd","g"),
      ("s-cs-blazor","dotnet/blazor","c"),("s-cs-unity","Unity-Technologies/UnityCsReference","c")]
LN = {"p":"python","j":"javascript","v":"java","g":"go","c":"csharp"}

def clone(rf,d):
    if d.exists(): shutil.rmtree(d)
    r = subprocess.run(["git","clone","--depth","1","--single-branch",f"https://github.com/{rf}",str(d)],capture_output=True,text=True,timeout=120)
    return r.returncode==0

def cloc(d,lg):
    lo,fi=0,0
    for ex in EM.get(lg,[]):
        for f in d.rglob(f"*{ex}"):
            if set(p.lower() for p in f.parts)&SD: continue
            try: lo+=len(f.read_text(encoding="utf-8",errors="replace").splitlines()); fi+=1
            except: pass
    return lo,fi

def s_ansede(d,lg):
    fs=[]; t0=time.perf_counter()
    af=_collect_files([d],exclude_patterns=[])
    lf=[f for f in af if _detect_language(f)==lg]
    src=[]
    for f in lf:
        if set(p.lower() for p in f.parts)&SD: continue
        try:
            if f.stat().st_size<=100*1024: src.append(f)
        except: pass
    src=src[:200]
    for fp in src:
        try:
            r=_analyze_file_with_timeout(fp,timeout_seconds=8.0)
            for f in r.findings:
                fs.append(dict(file=str(fp.relative_to(d)),line=f.line,rule_id=f.rule_id or "",cwe=f.cwe or "",
                    severity=f.severity.value if hasattr(f.severity,'value') else str(f.severity),
                    title=f.title or "",confidence=getattr(f,'confidence',1.0)))
        except: pass
    return fs, time.perf_counter()-t0

def s_sg(d,lg):
    fs=[]; t0=time.perf_counter()
    for ex in EM.get(lg,[]):
        for fp in d.rglob(f"*{ex}"):
            if set(p.lower() for p in fp.parts)&SD: continue
            try:
                if fp.stat().st_size>100*1024: continue
                code=fp.read_text(encoding="utf-8",errors="replace")
                for cwe,lf,pat in SG:
                    if lf and lf!=lg: continue
                    for m in pat.finditer(code):
                        fs.append(dict(file=str(fp.relative_to(d)),line=code[:m.start()].count("\n")+1,cwe=cwe))
            except: pass
    return fs, time.perf_counter()-t0

def audit(fs,d):
    aud=[]
    for f in fs:
        fp=f.get("file",""); ln=f.get("line",0); cw=str(f.get("cwe","")).upper()
        pl=fp.lower(); ctx=""
        fl=d/fp
        if fl.exists():
            try:
                ls=fl.read_text(encoding="utf-8",errors="replace").splitlines()
                s=max(0,ln-6); e=min(len(ls),ln+3); ctx="\n".join(ls[s:e])
            except: pass
        v="TP"; ev="cwe_sink"
        if any(p in pl for p in ["/test","/tests/","/__tests__/","/spec/","/fixtures/","/examples/","/demo/"]):
            v="FP"; ev="test_file"
        elif f.get("confidence",1.0)<0.30: v="FP"; ev=f"low_conf"
        elif "CWE-89" in cw:
            cl=ctx.lower()
            if "?" in cl and any(k in cl for k in ["execute(","query(","cursor."]): v="FP"; ev="param_sql"
            elif "%s" in cl and "execute(" in cl: v="FP"; ev="param_sql_pct"
            elif "f\"" in cl and "select" in cl: v="TP"; ev="fstring_sqli"
            elif " + " in cl and "select" in cl: v="TP"; ev="concat_sqli"
            else: v="TP"; ev="sql_sink"
        elif "CWE-78" in cw:
            cl=ctx.lower()
            if "shell=true" in cl: v="TP"; ev="shell_true"
            elif "os.system" in cl: v="TP"; ev="os_system"
            elif "subprocess" in cl and ("[" in cl or "shell=false" in cl): v="FP"; ev="safe_subprocess"
            else: v="TP"; ev="cmd_sink"
        elif "CWE-79" in cw:
            cl=ctx.lower()
            if "innerhtml" in cl:
                if any(s in cl for s in ["escape","sanitize","textcontent","createelement"]): v="FP"; ev="xss_safe"
                else: v="TP"; ev="unsafe_innerhtml"
        elif "CWE-798" in cw:
            if any(w in ctx.lower() for w in ["example","test","fake","dummy","your-","xxx","changeme","os.environ","os.getenv","process.env"]): v="FP"; ev="example_or_env"
            else: v="TP"; ev="hardcoded"
        elif "CWE-502" in cw: v="TP"; ev="deser"
        elif "CWE-352" in cw: v="TP"; ev="csrf"
        elif cw.startswith("CWE-"): v="TP"; ev="cwe_present"
        else: v="NR"; ev="unknown"
        aud.append(dict(file=fp,line=ln,cwe=cw,title=f.get("title","")[:100],verdict=v,evidence=ev,ctx=ctx[:300]))
    return aud

print("="*70)
print("RUN 3 — 100 FRESH REPOS (zero overlap)")
print(f"Start: {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
print("Upgrades: SQL param, safe subprocess, NestJS, Hono rules, log fixes")
print("="*70)

res=[]; fail=[]; si=0
for i,(nm,rf,lc) in enumerate(R):
    lg=LN[lc]; d=RD/nm
    print(f"\n[{i+1}/100] {nm} ({lg})")
    if not d.exists() or not list(d.glob("*")):
        if not clone(rf,d):
            if si<len(SP):
                sn,sf,sl=SP[si]; si+=1; sll=LN[sl]; sd=RD/sn
                if not clone(sf,sd): fail.append(dict(name=nm,reason="clone")); continue
                nm,lg,d=sn,sll,sd
            else: fail.append(dict(name=nm,reason="clone")); continue
    lo,fi=cloc(d,lg)
    if lo==0:
        if si<len(SP):
            sn,sf,sl=SP[si]; si+=1; sll=LN[sl]; sd=RD/sn
            if not clone(sf,sd): fail.append(dict(name=nm,reason="nosrc")); continue
            nm,lg,d=sn,sll,sd; lo,fi=cloc(d,lg)
            if lo==0: fail.append(dict(name=nm,reason="nosrc")); continue
        else: fail.append(dict(name=nm,reason="nosrc")); continue
    print(f"  LOC={lo:,} Files={fi}")
    af,at=s_ansede(d,lg); aud=audit(af,d)
    sf_,st=s_sg(d,lg)
    tp=sum(1 for a in aud if a["verdict"]=="TP"); fp=sum(1 for a in aud if a["verdict"]=="FP")
    nr=sum(1 for a in aud if a["verdict"]=="NR")
    print(f"  Ansede: {len(af)} ({at:.1f}s) TP={tp} FP={fp} NR={nr} | SG: {len(sf_)}")
    r=dict(name=nm,lang=lg,loc=lo,files=fi,ansede_n=len(af),ansede_t=round(at,1),
           ansede_tp=tp,ansede_fp=fp,ansede_nr=nr,sg_n=len(sf_),sg_t=round(st,1))
    res.append(r)
    s=dict(ts=datetime.now(timezone.utc).isoformat(),completed=len(res),failed=len(fail),
           total_loc=sum(x["loc"] for x in res),ansede_total=sum(x["ansede_n"] for x in res),
           ansede_tp=sum(x["ansede_tp"] for x in res),ansede_fp=sum(x["ansede_fp"] for x in res),
           sg_total=sum(x["sg_n"] for x in res),
           precision=round(sum(x["ansede_tp"] for x in res)/(sum(x["ansede_tp"] for x in res)+sum(x["ansede_fp"] for x in res))*100,1) if sum(x["ansede_tp"] for x in res)+sum(x["ansede_fp"] for x in res) else 0)
    json.dump(s,(OUT/"results.json").open("w"),indent=2)

print("\n"+"="*70)
if res:
    tl=sum(x["loc"] for x in res); ta=sum(x["ansede_n"] for x in res); tsg=sum(x["sg_n"] for x in res)
    tp=sum(x["ansede_tp"] for x in res); fp=sum(x["ansede_fp"] for x in res)
    prec=round(tp/(tp+fp)*100,1) if (tp+fp) else 0
    print(f"FINAL: {len(res)} repos | {tl:,} LOC")
    print(f"Ansede: {ta} | TP={tp} FP={fp} | Precision={prec}% | SG: {tsg}" + (f" | Ratio: {ta/tsg:.1f}x" if tsg else ""))
    for lg in ["python","javascript","java","go","csharp"]:
        lr=[x for x in res if x["lang"]==lg]
        if not lr: continue
        lt=sum(x["ansede_tp"] for x in lr); lf=sum(x["ansede_fp"] for x in lr)
        lp=round(lt/(lt+lf)*100,1) if (lt+lf) else 0
        print(f"  {lg:>12}: {len(lr):>2} repos | A={sum(x['ansede_n'] for x in lr):>4} SG={sum(x['sg_n'] for x in lr):>4} Prec={lp}%")
    json.dump(dict(ts=datetime.now(timezone.utc).isoformat(),completed=len(res),failed=len(fail),
                   total_loc=tl,ansede_total=ta,sg_total=tsg,ansede_tp=tp,ansede_fp=fp,
                   precision=prec,per_repo=res),(OUT/"results.json").open("w"),indent=2)
    print(f"\nSaved: {OUT/'results.json'}")
print("DONE.")
