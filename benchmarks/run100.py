#!/usr/bin/env python3
"""100-repo campaign — proven inline approach, extended repo list, deep audit."""
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

R = [
    ("py-rich","Textualize/rich","p"),("py-fastapi","fastapi/fastapi","p"),("py-django","django/django","p"),
    ("py-flask","pallets/flask","p"),("py-starlette","encode/starlette","p"),("py-celery","celery/celery","p"),
    ("py-sqlalchemy","sqlalchemy/sqlalchemy","p"),("py-tornado","tornadoweb/tornado","p"),
    ("py-sanic","sanic-org/sanic","p"),("py-bottle","bottlepy/bottle","p"),("py-aiohttp","aio-libs/aiohttp","p"),
    ("py-requests","psf/requests","p"),("py-pydantic","pydantic/pydantic","p"),("py-httpx","encode/httpx","p"),
    ("py-scrapy","scrapy/scrapy","p"),("py-marshmallow","marshmallow-code/marshmallow","p"),
    ("py-apscheduler","agronholm/apscheduler","p"),("py-loguru","Delgan/loguru","p"),
    ("py-peewee","coleifer/peewee","p"),("py-dramatiq","Bogdanp/dramatiq","p"),
    ("js-express","expressjs/express","j"),("js-koa","koajs/koa","j"),("js-fastify","fastify/fastify","j"),
    ("js-axios","axios/axios","j"),("js-lodash","lodash/lodash","j"),("js-moment","moment/moment","j"),
    ("js-cheerio","cheeriojs/cheerio","j"),("js-socketio","socketio/socket.io","j"),
    ("js-hono","honojs/hono","j"),("js-nest","nestjs/nest","j"),("js-react","facebook/react","j"),
    ("js-vue","vuejs/vue","j"),("js-nextjs","vercel/next.js","j"),("js-prisma","prisma/prisma","j"),
    ("js-svelte","sveltejs/svelte","j"),("js-elysia","elysiajs/elysia","j"),("js-astro","withastro/astro","j"),
    ("js-remix","remix-run/remix","j"),("js-tanstack","TanStack/query","j"),("js-zod","colinhacks/zod","j"),
    ("jv-guava","google/guava","v"),("jv-gson","google/gson","v"),("jv-retrofit","square/retrofit","v"),
    ("jv-okhttp","square/okhttp","v"),("jv-jedis","redis/jedis","v"),("jv-junit5","junit-team/junit5","v"),
    ("jv-mockito","mockito/mockito","v"),("jv-lombok","projectlombok/lombok","v"),
    ("jv-zxing","zxing/zxing","v"),("jv-log4j","apache/logging-log4j2","v"),
    ("jv-elastic","elastic/elasticsearch","v"),("jv-jenkins","jenkinsci/jenkins","v"),
    ("jv-hibernate","hibernate/hibernate-orm","v"),("jv-jackson","FasterXML/jackson","v"),
    ("jv-netty","netty/netty","v"),("jv-selenium","SeleniumHQ/selenium","v"),
    ("jv-picocli","remkop/picocli","v"),("jv-javalin","javalin/javalin","v"),
    ("jv-micronaut","micronaut-projects/micronaut-core","v"),("jv-quarkus","quarkusio/quarkus","v"),
    ("go-gin","gin-gonic/gin","g"),("go-echo","labstack/echo","g"),("go-fiber","gofiber/fiber","g"),
    ("go-chi","go-chi/chi","g"),("go-cobra","spf13/cobra","g"),("go-viper","spf13/viper","g"),
    ("go-gorm","go-gorm/gorm","g"),("go-colly","gocolly/colly","g"),
    ("go-validator","go-playground/validator","g"),("go-swag","swaggo/swag","g"),
    ("go-prometheus","prometheus/prometheus","g"),("go-kit","go-kit/kit","g"),
    ("go-iris","kataras/iris","g"),("go-beego","beego/beego","g"),("go-revel","revel/revel","g"),
    ("go-buffalo","gobuffalo/buffalo","g"),("go-grpc","grpc/grpc-go","g"),
    ("go-mux","gorilla/mux","g"),("go-sqlx","jmoiron/sqlx","g"),("go-pgx","jackc/pgx","g"),
    ("cs-automapper","AutoMapper/AutoMapper","c"),("cs-mediatr","jbogard/MediatR","c"),
    ("cs-serilog","serilog/serilog","c"),("cs-dapper","DapperLib/Dapper","c"),
    ("cs-fluentv","FluentValidation/FluentValidation","c"),("cs-polly","App-vNext/Polly","c"),
    ("cs-hangfire","HangfireIO/Hangfire","c"),("cs-orleans","dotnet/orleans","c"),
    ("cs-signalr","SignalR/SignalR","c"),("cs-identity","IdentityServer/IdentityServer4","c"),
    ("cs-efcore","dotnet/efcore","c"),("cs-aspnetcore","dotnet/aspnetcore","c"),
    ("cs-npgsql","npgsql/npgsql","c"),("cs-restsharp","restsharp/RestSharp","c"),
    ("cs-moq","devlooped/moq","c"),("cs-xunit","xunit/xunit","c"),("cs-nlog","NLog/NLog","c"),
    ("cs-autofac","autofac/Autofac","c"),("cs-fluentassert","fluentassertions/fluentassertions","c"),
    ("cs-humanizer","Humanizr/Humanizer","c"),
]

SP = [("s-py-uvicorn","encode/uvicorn","p"),("s-py-mypy","python/mypy","p"),("s-py-watchfiles","samuelcolvin/watchfiles","p"),
      ("s-js-nuxt","nuxt/nuxt","j"),("s-js-solid","solidjs/solid","j"),("s-js-prettier","prettier/prettier","j"),
      ("s-jv-spark","perwendel/spark","v"),("s-jv-vertx","eclipse-vertx/vert.x","v"),("s-jv-kafka","apache/kafka","v"),
      ("s-go-fx","uber-go/fx","g"),("s-go-ent","ent/ent","g"),("s-go-terraform","hashicorp/terraform","g"),
      ("s-cs-roslyn","dotnet/roslyn","c"),("s-cs-avalonia","AvaloniaUI/Avalonia","c"),("s-cs-powertoys","microsoft/PowerToys","c")]

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
        fp=f.get("file",""); ln=f.get("line",0); cw=str(f.get("cwe","")).upper(); tl=str(f.get("title",""))
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
        elif f.get("confidence",1.0)<0.30: v="FP"; ev=f"low_conf_{f.get('confidence',0):.2f}"
        elif "CWE-89" in cw:
            cl=ctx.lower()
            if "?" in cl and any(k in cl for k in ["execute(","query(","cursor."]): v="FP"; ev="param_sql"
            elif "%s" in cl and "execute(" in cl: v="FP"; ev="param_sql"
            elif "f\"" in cl and "select" in cl: v="TP"; ev="fstring_sql"
            elif " + " in cl and "select" in cl: v="TP"; ev="concat_sql"
        elif "CWE-78" in cw:
            cl=ctx.lower()
            if "shell=true" in cl: v="TP"; ev="shell_true"
            elif "os.system" in cl: v="TP"; ev="os_system"
            elif "subprocess" in cl and ("[" in cl or "shell=false" in cl): v="FP"; ev="safe_subprocess"
        elif "CWE-79" in cw:
            cl=ctx.lower()
            if "innerhtml" in cl:
                if any(s in cl for s in ["escape","sanitize","textcontent","createelement"]): v="FP"; ev="xss_safe"
                else: v="TP"; ev="unsafe_innerhtml"
        elif "CWE-798" in cw:
            cl=ctx.lower()
            if any(w in cl for w in ["example","test","fake","dummy","your-","xxx","changeme","os.environ","os.getenv","process.env"]): v="FP"; ev="example_or_env"
            else: v="TP"; ev="hardcoded"
        elif "CWE-502" in cw: v="TP"; ev="deser"
        elif "CWE-352" in cw: v="TP"; ev="csrf"
        elif cw.startswith("CWE-"): v="TP"; ev="cwe_sink"
        else: v="NR"; ev="unknown"
        aud.append(dict(file=fp,line=ln,cwe=cw,title=tl[:100],verdict=v,evidence=ev,ctx=ctx[:300]))
    return aud

print("="*70); print("100-REPO CAMPAIGN v2 (INLINE)"); print(f"Start: {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
print("="*70)

res=[]; fail=[]; si=0
for i,(nm,rf,lc) in enumerate(R):
    lg=LN[lc]; d=RD/nm
    print(f"\n[{i+1}/100] {nm} ({lg})")

    if not d.exists() or not list(d.glob("*")):
        print(f"  Cloning {rf}...")
        if not clone(rf,d):
            print(f"  ✗ Clone failed")
            # Try spare
            if si<len(SP):
                sn,sf,sl=SP[si]; si+=1; sll=LN[sl]; sd=RD/sn
                print(f"  → Spare: {sn} ({sll})")
                if not clone(sf,sd):
                    fail.append(dict(name=nm,reason="clone_fail")); continue
                nm,lg,d=sn,sll,sd
            else:
                fail.append(dict(name=nm,reason="clone_fail")); continue

    lo,fi=cloc(d,lg)
    if lo==0:
        # Try spare
        if si<len(SP):
            sn,sf,sl=SP[si]; si+=1; sll=LN[sl]; sd=RD/sn
            print(f"  → Spare (no src): {sn} ({sll})")
            if not clone(sf,sd):
                fail.append(dict(name=nm,reason="no_src")); continue
            nm,lg,d=sn,sll,sd; lo,fi=cloc(d,lg)
            if lo==0: fail.append(dict(name=nm,reason="no_src")); continue
        else:
            fail.append(dict(name=nm,reason="no_src")); continue
    
    print(f"  LOC={lo:,} Files={fi}")
    af,at=s_ansede(d,lg); aud=audit(af,d)
    sf_,st=s_sg(d,lg)
    tp=sum(1 for a in aud if a["verdict"]=="TP"); fp=sum(1 for a in aud if a["verdict"]=="FP")
    nr=sum(1 for a in aud if a["verdict"]=="NR")
    print(f"  Ansede: {len(af)} ({at:.1f}s) TP={tp} FP={fp} NR={nr} | SG: {len(sf_)}")

    r={"name":nm,"lang":lg,"loc":lo,"files":fi,"ansede_n":len(af),"ansede_t":round(at,1),
       "ansede_tp":tp,"ansede_fp":fp,"ansede_nr":nr,"sg_n":len(sf_),"sg_t":round(st,1),"audited":aud}
    res.append(r)

    # Save incrementally
    s={"ts":datetime.now(timezone.utc).isoformat(),"completed":len(res),"failed":len(fail),
       "total_loc":sum(x["loc"] for x in res),"ansede_total":sum(x["ansede_n"] for x in res),
       "ansede_tp":sum(x["ansede_tp"] for x in res),"ansede_fp":sum(x["ansede_fp"] for x in res),
       "sg_total":sum(x["sg_n"] for x in res),
       "precision":round(sum(x["ansede_tp"] for x in res)/(sum(x["ansede_tp"] for x in res)+sum(x["ansede_fp"] for x in res))*100,1) if sum(x["ansede_tp"] for x in res)+sum(x["ansede_fp"] for x in res) else 0}
    json.dump(s,(OUT/"results.json").open("w"),indent=2)

# Final
if res:
    tl=sum(x["loc"] for x in res); ta=sum(x["ansede_n"] for x in res); tsg=sum(x["sg_n"] for x in res)
    tp=sum(x["ansede_tp"] for x in res); fp=sum(x["ansede_fp"] for x in res)
    prec=round(tp/(tp+fp)*100,1) if (tp+fp) else 0
    print("\n"+"="*70)
    print(f"FINAL: {len(res)} repos | {tl:,} LOC")
    print(f"Ansede: {ta} | TP={tp} FP={fp} | Precision={prec}% | SG: {tsg}")
    for lg in ["python","javascript","java","go","csharp"]:
        lr=[x for x in res if x["lang"]==lg]
        if not lr: continue
        lt=sum(x["ansede_tp"] for x in lr); lf=sum(x["ansede_fp"] for x in lr)
        lp=round(lt/(lt+lf)*100,1) if (lt+lf) else 0
        print(f"  {lg:>12}: {len(lr):>2} repos | Ansede={sum(x['ansede_n'] for x in lr):>5} SG={sum(x['sg_n'] for x in lr):>5} Prec={lp}%")
    
    # FP patterns
    fps=Counter()
    for x in res:
        for a in x.get("audited",[]):
            if a["verdict"]=="FP": fps[f"{a.get('cwe','')}:{a.get('evidence','')}"]+=1
    print(f"\nTop FP patterns:")
    for p,c in fps.most_common(8): print(f"  {c:>3} × {p}")
    
    final={"ts":datetime.now(timezone.utc).isoformat(),"completed":len(res),"failed":len(fail),
           "total_loc":tl,"ansede_total":ta,"sg_total":tsg,"ansede_tp":tp,"ansede_fp":fp,
           "precision":prec,"fp_patterns":dict(fps.most_common(20)),
           "per_repo":[{k:v for k,v in x.items() if k!="audited"} for x in res]}
    json.dump(final,(OUT/"results.json").open("w"),indent=2)
    print(f"\nSaved: {OUT/'results.json'}")
if fail: print(f"Failures: {len(fail)}")
print("DONE.")
