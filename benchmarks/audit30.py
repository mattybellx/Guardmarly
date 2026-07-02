#!/usr/bin/env python3
"""Targeted re-scan + deep audit of 30 cloned repos to find FP patterns for engine upgrades."""
import json, sys, time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static.cli import _detect_language, _collect_files, _analyze_file_with_timeout

REPOS_DIR = Path("campaign/v2_100/repos")
SD = {"node_modules","vendor",".git","dist","build","__pycache__",".next",".nuxt","target","bin","obj","coverage",".venv","tests","test","__tests__","spec","fixtures","examples","site-packages",".tox","eggs",".eggs","docs","doc","samples","demo",".github",".circleci"}
EM = {"python":[".py",".pyi"],"javascript":[".js",".jsx",".ts",".tsx",".mjs"],"java":[".java"],"go":[".go"],"csharp":[".cs"]}

def audit_finding(f, d):
    fp = f.get("file",""); ln = f.get("line",0); cw = str(f.get("cwe","")).upper()
    pl = fp.lower()
    ctx = ""
    fl = d / fp
    if fl.exists():
        try:
            ls = fl.read_text(encoding="utf-8",errors="replace").splitlines()
            s = max(0,ln-6); e = min(len(ls),ln+3); ctx = "\n".join(ls[s:e])
        except: pass
    
    v = "TP"; ev = "cwe_sink"; conf = 0.85
    
    # Test/file check
    if any(p in pl for p in ["/test","/tests/","/__tests__/","/spec/","/fixtures/","/examples/","/demo/"]):
        v="FP"; ev="test_file"; conf=0.95
    elif f.get("confidence",1.0) < 0.30: v="FP"; ev=f"low_conf"; conf=0.90
    
    # SQL injection
    elif "CWE-89" in cw:
        cl = ctx.lower()
        if "?" in cl and any(k in cl for k in ["execute(","query(","cursor."]): v="FP"; ev="param_sql_question"; conf=0.90
        elif "%s" in cl and "execute(" in cl: v="FP"; ev="param_sql_percent"; conf=0.90
        elif ":$" in cl or ":param" in cl: v="FP"; ev="named_param"; conf=0.90
        elif "f\"" in cl and "select" in cl: v="TP"; ev="fstring_sqli"; conf=0.90
        elif " + " in cl and "select" in cl: v="TP"; ev="concat_sqli"; conf=0.90
        elif ".format(" in cl and "select" in cl: v="TP"; ev="format_sqli"; conf=0.90
        elif "text(" in cl and "sqlalchemy" in cl: v="FP"; ev="sqlalchemy_text"; conf=0.80
        else: v="TP"; ev="generic_sqli"; conf=0.75
    
    # Command injection
    elif "CWE-78" in cw:
        cl = ctx.lower()
        if "shell=true" in cl: v="TP"; ev="shell_true"; conf=0.95
        elif "os.system" in cl: v="TP"; ev="os_system"; conf=0.95
        elif "subprocess" in cl and ("[" in cl.split("subprocess")[1][:200] if "subprocess" in cl else False): v="FP"; ev="list_form_args"; conf=0.90
        elif "subprocess" in cl and "shell=false" in cl: v="FP"; ev="shell_false"; conf=0.90
        else: v="TP"; ev="cmd_sink"; conf=0.70
    
    # XSS
    elif "CWE-79" in cw:
        cl = ctx.lower()
        if "innerhtml" in cl:
            if any(s in cl for s in ["escape","sanitize","textcontent","createelement","encode"]): v="FP"; ev="xss_sanitized"; conf=0.88
            elif "innerhtml =" in cl and "+" not in cl.split("innerhtml =")[1][:80]: v="FP"; ev="static_innerhtml"; conf=0.85
            else: v="TP"; ev="dynamic_innerhtml"; conf=0.85
        elif "document.write" in cl:
            if any(s in cl for s in ["encode","escape"]): v="FP"; ev="xss_safe_write"; conf=0.88
            else: v="TP"; ev="document_write"; conf=0.85
        elif "dangerouslySetInnerHTML" in cl: v="TP"; ev="react_dangerous"; conf=0.90
        else: v="TP"; ev="xss_sink"; conf=0.70
    
    # Hardcoded secrets
    elif "CWE-798" in cw:
        cl = ctx.lower()
        if any(w in cl for w in ["example","test","fake","dummy","your-","xxx","changeme","placeholder","sample"]): v="FP"; ev="example_value"; conf=0.92
        elif any(w in cl for w in ["os.environ","os.getenv","process.env","env.get","config.get","getenv("]): v="FP"; ev="reads_from_env"; conf=0.92
        else: v="TP"; ev="hardcoded_secret"; conf=0.82
    
    # Path traversal
    elif "CWE-22" in cw:
        cl = ctx.lower()
        if any(w in cl for w in ["basedir","base_dir","root_dir","safe_root","resolve_path","sanitize_path","validate_path"]): v="FP"; ev="path_sanitized"; conf=0.85
        else: v="TP"; ev="path_traversal"; conf=0.75
    
    # CSRF
    elif "CWE-352" in cw:
        v="TP"; ev="csrf_disabled"; conf=0.90
    
    # Deserialization
    elif "CWE-502" in cw:
        cl = ctx.lower()
        if "yaml.safe_load" in cl: v="FP"; ev="safe_yaml"; conf=0.90
        elif "json.load" in cl: v="FP"; ev="json_deser"; conf=0.85
        else: v="TP"; ev="unsafe_deser"; conf=0.88
    
    # Auth/IDOR
    elif "CWE-862" in cw or "CWE-639" in cw or "CWE-306" in cw:
        cl = ctx.lower()
        if any(w in cl for w in ["@useguards","@authguard","@authenticated","@roles","@permissions","@authorize"]): v="FP"; ev="auth_guard_present"; conf=0.82
        elif any(w in cl for w in ["user_id","owner_id","current_user","getuserbyid","findbyidanduserid"]): v="FP"; ev="ownership_check"; conf=0.82
        else: v="TP"; ev="missing_auth"; conf=0.70
    
    elif cw.startswith("CWE-"): v="TP"; ev="cwe_sink"; conf=0.65
    else: v="NR"; ev="unknown"; conf=0.40
    
    return dict(file=fp, line=ln, cwe=cw, rule_id=f.get("rule_id",""), title=f.get("title","")[:120],
                verdict=v, evidence=ev, confidence=conf, ctx=ctx[:400])

print("="*70)
print("TARGETED DEEP AUDIT — 30 cloned repos")
print("="*70)

all_audited = []
stats = Counter()

for repo_dir in sorted(REPOS_DIR.iterdir()):
    if not repo_dir.is_dir(): continue
    name = repo_dir.name
    
    # Detect language from name prefix
    if name.startswith("py-"): lang = "python"
    elif name.startswith("js-"): lang = "javascript"
    elif name.startswith("jv-"): lang = "java"
    elif name.startswith("go-"): lang = "go"
    elif name.startswith("cs-"): lang = "csharp"
    else: continue
    
    # Scan
    all_files = _collect_files([repo_dir], exclude_patterns=[])
    lang_files = [f for f in all_files if _detect_language(f) == lang]
    src = []
    for f in lang_files:
        if set(p.lower() for p in f.parts) & SD: continue
        try:
            if f.stat().st_size <= 100*1024: src.append(f)
        except: pass
    src = src[:200]
    
    findings = []
    for fp in src:
        try:
            r = _analyze_file_with_timeout(fp, timeout_seconds=8.0)
            for ff in r.findings:
                findings.append(dict(file=str(fp.relative_to(repo_dir)), line=ff.line,
                    rule_id=ff.rule_id or "", cwe=ff.cwe or "",
                    severity=ff.severity.value if hasattr(ff.severity,'value') else str(ff.severity),
                    title=ff.title or "", confidence=getattr(ff,'confidence',1.0)))
        except: pass
    
    # Audit
    repo_tp = repo_fp = 0
    for ff in findings:
        a = audit_finding(ff, repo_dir)
        a["repo"] = name; a["lang"] = lang
        all_audited.append(a)
        if a["verdict"] == "TP": repo_tp += 1
        elif a["verdict"] == "FP": repo_fp += 1
        stats[a["verdict"]] += 1
        stats[f"v_{a['evidence']}"] += 1
    
    print(f"  {name}: {len(findings):>4} findings → TP={repo_tp} FP={repo_fp}")

# Summary
total_tp = sum(1 for a in all_audited if a["verdict"] == "TP")
total_fp = sum(1 for a in all_audited if a["verdict"] == "FP")
total_nr = sum(1 for a in all_audited if a["verdict"] == "NR")
prec = round(total_tp/(total_tp+total_fp)*100,1) if (total_tp+total_fp) else 0

print(f"\n{'='*70}")
print(f"DEEP AUDIT: {len(all_audited)} findings | TP={total_tp} FP={total_fp} NR={total_nr} | Precision={prec}%")

# FP patterns
fp_pats = Counter()
fp_examples = []
for a in all_audited:
    if a["verdict"] == "FP":
        fp_pats[f"{a.get('cwe','')}:{a['evidence']}"] += 1
        if len(fp_examples) < 20:
            fp_examples.append(a)

print(f"\nTop FP patterns:")
for pat, cnt in fp_pats.most_common(12):
    print(f"  {cnt:>3} × {pat}")

print(f"\nFP examples (for upgrade analysis):")
for a in fp_examples[:8]:
    print(f"  [{a['cwe']}] {a['evidence']} — {a['repo']}/{a['file']}:{a['line']}")
    for line in a['ctx'].split("\n")[:3]:
        print(f"    {line}")

# Save
out = {
    "total_audited": len(all_audited),
    "tp": total_tp, "fp": total_fp, "nr": total_nr, "precision": prec,
    "fp_patterns": dict(fp_pats.most_common(20)),
    "fp_examples": [{k:v for k,v in a.items() if k!="ctx"} for a in fp_examples],
    "per_repo": {r["repo"]: {"tp": sum(1 for a in all_audited if a["repo"]==r["repo"] and a["verdict"]=="TP"),
                              "fp": sum(1 for a in all_audited if a["repo"]==r["repo"] and a["verdict"]=="FP")}
                 for r in sorted(all_audited, key=lambda x: x["repo"])}
}
json.dump(out, Path("campaign/v2_100/deep_audit.json").open("w"), indent=2)
print(f"\nSaved: campaign/v2_100/deep_audit.json")
print("DONE.")
