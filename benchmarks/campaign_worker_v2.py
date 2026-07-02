
import json, os, re, sys, time
from pathlib import Path
cfg = json.loads(sys.argv[1])
sys.path.insert(0, cfg["project_src"])
from ansede_static.cli import _detect_language, _collect_files, _analyze_file_with_timeout

repo_dir = Path(cfg["repo_dir"]); lang = cfg["lang"]
skip_dirs = set(cfg["skip_dirs"]); max_kb = cfg["max_kb"]; max_files = cfg["max_files"]
sg_pats = [(c,l,re.compile(p,re.I)) for c,l,p in cfg["sg_patterns"]]
ext_map = cfg["ext_map"]

def count_loc(d):
    loc, files = 0, 0
    for ext in ext_map.get(lang,[]):
        for f in d.rglob(f"*{ext}"):
            if set(p.lower() for p in f.parts) & skip_dirs: continue
            try: loc += len(f.read_text(encoding="utf-8",errors="replace").splitlines()); files += 1
            except: pass
    return loc, files

def is_sqli_safe(ctx):
    c = ctx.lower()
    if "?" in c and any(k in c for k in ["execute(","query(","cursor."]): return True
    if "%s" in c and "execute(" in c: return True
    if "f\"" in c and "select" in c: return False
    if " + " in c and "select" in c: return False
    if "format(" in c and "select" in c: return False
    return None

def is_cmd_safe(ctx):
    c = ctx.lower()
    if "shell=true" in c: return False
    if "os.system" in c: return False
    if "subprocess" in c and "shell=false" in c: return True
    if "subprocess" in c and "[" in c: return True
    return None

def is_xss_safe(ctx):
    c = ctx.lower()
    if "innerhtml" in c:
        if any(s in c for s in ["escape","sanitize","textcontent","createelement"]): return True
        return False
    if "document.write" in c: return any(s in c for s in ["encode","escape"])
    return None

def scan_ansede(d):
    findings = []
    t0 = time.perf_counter()
    all_files = _collect_files([d], exclude_patterns=[])
    lang_files = [f for f in all_files if _detect_language(f) == lang]
    src = []
    for f in lang_files:
        if set(p.lower() for p in f.parts) & skip_dirs: continue
        try:
            if f.stat().st_size <= max_kb * 1024: src.append(f)
        except: pass
    src = src[:max_files]
    for fp in src:
        try:
            r = _analyze_file_with_timeout(fp, timeout_seconds=8.0)
            for f in r.findings:
                findings.append(dict(file=str(fp.relative_to(d)),line=f.line,
                    rule_id=f.rule_id or "",cwe=f.cwe or "",
                    severity=f.severity.value if hasattr(f.severity,'value') else str(f.severity),
                    title=f.title or "",confidence=getattr(f,'confidence',1.0)))
        except: pass
    return findings, time.perf_counter()-t0

def scan_sg(d):
    findings = []
    t0 = time.perf_counter()
    for ext in ext_map.get(lang,[]):
        for fp in d.rglob(f"*{ext}"):
            if set(p.lower() for p in fp.parts) & skip_dirs: continue
            try:
                if fp.stat().st_size > max_kb * 1024: continue
                code = fp.read_text(encoding="utf-8",errors="replace")
                for cwe,lf,pat in sg_pats:
                    if lf and lf != lang: continue
                    for m in pat.finditer(code):
                        findings.append(dict(file=str(fp.relative_to(d)),line=code[:m.start()].count("\n")+1,cwe=cwe))
            except: pass
    return findings, time.perf_counter()-t0

def deep_audit(findings, d):
    audited = []
    for f in findings:
        fp_path = f.get("file",""); line = f.get("line",0)
        cwe = str(f.get("cwe","")).upper(); title = str(f.get("title",""))
        full = d / fp_path
        ctx = ""
        if full.exists():
            try:
                lines = full.read_text(encoding="utf-8",errors="replace").splitlines()
                s = max(0,line-6); e = min(len(lines),line+3)
                ctx = "\n".join(lines[s:e])
            except: pass
        verdict = "NEEDS_REVIEW"; evidence = ""
        # Test/file check
        pl = fp_path.lower()
        if any(p in pl for p in ["/test","/tests/","/__tests__/","/spec/","/fixtures/","/examples/","/demo/"]):
            verdict = "FP"; evidence = "test_fixture_file"
        elif f.get("confidence",1.0) < 0.30:
            verdict = "FP"; evidence = f"low_confidence_{f.get('confidence',0):.2f}"
        elif "CWE-89" in cwe:
            s = is_sqli_safe(ctx)
            if s is True: verdict = "FP"; evidence = "parameterized_sql"
            elif s is False: verdict = "TP"; evidence = "sql_concat_or_format"
            else: verdict = "TP"; evidence = "sql_sink_present"
        elif "CWE-78" in cwe:
            s = is_cmd_safe(ctx)
            if s is True: verdict = "FP"; evidence = "safe_subprocess_list"
            elif s is False: verdict = "TP"; evidence = "shell_true_or_os_system"
            else: verdict = "TP"; evidence = "cmd_sink_present"
        elif "CWE-79" in cwe:
            s = is_xss_safe(ctx)
            if s is True: verdict = "FP"; evidence = "xss_sanitized"
            elif s is False: verdict = "TP"; evidence = "unsafe_dom_write"
            else: verdict = "TP"; evidence = "xss_sink_present"
        elif "CWE-502" in cwe: verdict = "TP"; evidence = "unsafe_deserialization"
        elif "CWE-22" in cwe: verdict = "TP"; evidence = "path_traversal_sink"
        elif "CWE-798" in cwe:
            if any(w in ctx.lower() for w in ["example","test","fake","dummy","your-","xxx","changeme","os.environ","os.getenv","process.env"]):
                verdict = "FP"; evidence = "example_or_env_var"
            else: verdict = "TP"; evidence = "hardcoded_secret"
        elif "CWE-352" in cwe and "csrf" in ctx.lower():
            verdict = "TP"; evidence = "csrf_disabled"
        elif cwe.startswith("CWE-"): verdict = "TP"; evidence = "cwe_sink_present"
        
        audited.append(dict(file=fp_path,line=line,cwe=cwe,rule_id=f.get("rule_id",""),
            title=title[:120],verdict=verdict,evidence=evidence,ctx=ctx[:400]))
    return audited

loc, files = count_loc(repo_dir)
if loc == 0: print(json.dumps(dict(status="no_files"))); sys.exit(0)

af, at = scan_ansede(repo_dir)
audited = deep_audit(af, repo_dir)
sf, st = scan_sg(repo_dir)
tp = sum(1 for a in audited if a["verdict"]=="TP")
fp = sum(1 for a in audited if a["verdict"]=="FP")
nr = sum(1 for a in audited if a["verdict"]=="NEEDS_REVIEW")

print(json.dumps(dict(status="ok",loc=loc,files=files,
    ansede_n=len(af),ansede_t=round(at,1),ansede_tp=tp,ansede_fp=fp,ansede_nr=nr,
    sg_n=len(sf),sg_t=round(st,1),audited=audited)))
