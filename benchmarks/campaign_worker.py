#!/usr/bin/env python3
"""Worker script — runs in subprocess for per-repo isolation."""
import json, os, re, sys, time
from pathlib import Path

# Read config from args
config = json.loads(sys.argv[1])
repo_dir = Path(config["repo_dir"])
lang = config["lang"]
skip_dirs = set(config["skip_dirs"])
max_file_kb = config["max_file_kb"]
max_files = config["max_files"]
sg_patterns_raw = config["sg_patterns"]
ext_map = config["ext_map"]
project_src = config["project_src"]

sys.path.insert(0, project_src)
from ansede_static.cli import _detect_language, _collect_files, _analyze_file_with_timeout

# Rebuild compiled regex patterns
sg_patterns = []
for cwe, lang_filt, pat_str in sg_patterns_raw:
    try:
        sg_patterns.append((cwe, lang_filt, re.compile(pat_str, re.I)))
    except:
        pass

def count_loc(d):
    loc, files = 0, 0
    for ext in ext_map.get(lang, []):
        for f in d.rglob(f"*{ext}"):
            parts = set(p.lower() for p in f.parts)
            if parts & skip_dirs:
                continue
            try:
                loc += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
                files += 1
            except OSError:
                pass
    return loc, files

def scan_ansede(d):
    findings = []
    t0 = time.perf_counter()
    all_files = _collect_files([d], exclude_patterns=[])
    lang_files = [f for f in all_files if _detect_language(f) == lang]
    src = []
    for f in lang_files:
        parts = set(p.lower() for p in f.parts)
        if parts & skip_dirs:
            continue
        try:
            if f.stat().st_size <= max_file_kb * 1024:
                src.append(f)
        except OSError:
            pass
    src = src[:max_files]
    for fp in src:
        try:
            r = _analyze_file_with_timeout(fp, timeout_seconds=8.0)
            for f in r.findings:
                findings.append(dict(
                    file=str(fp.relative_to(d)),
                    line=f.line,
                    rule_id=f.rule_id,
                    cwe=f.cwe or "",
                    severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    title=f.title,
                    agent=getattr(f, 'agent', ''),
                    confidence=getattr(f, 'confidence', 1.0),
                ))
        except Exception:
            pass
    return findings, time.perf_counter() - t0

def scan_sg(d):
    findings = []
    t0 = time.perf_counter()
    for ext in ext_map.get(lang, []):
        for fp in d.rglob(f"*{ext}"):
            parts = set(p.lower() for p in fp.parts)
            if parts & skip_dirs:
                continue
            try:
                if fp.stat().st_size > max_file_kb * 1024:
                    continue
                code = fp.read_text(encoding="utf-8", errors="replace")
                for cwe, lang_filt, pat in sg_patterns:
                    if lang_filt and lang_filt != lang:
                        continue
                    for m in pat.finditer(code):
                        line = code[:m.start()].count("\n") + 1
                        findings.append(dict(
                            file=str(fp.relative_to(d)),
                            line=line,
                            cwe=cwe,
                        ))
            except Exception:
                pass
    return findings, time.perf_counter() - t0

def audit(findings, d):
    tp = fp = nr = 0
    for f in findings:
        fp_path = f.get("file", "")
        line = f.get("line", 0)
        cwe = str(f.get("cwe", "")).upper()
        if f.get("confidence", 1.0) < 0.35:
            fp += 1
            continue
        code_ctx = ""
        full = d / fp_path
        if full.exists():
            try:
                lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
                s = max(0, line - 2)
                e = min(len(lines), line + 1)
                code_ctx = "\n".join(lines[s:e])
            except OSError:
                pass
        if "subprocess" in code_ctx.lower() and "shell=True" in code_ctx:
            tp += 1
        elif "innerHTML" in code_ctx or "document.write" in code_ctx:
            tp += 1
        elif "pickle.load" in code_ctx or "ObjectInputStream" in code_ctx:
            tp += 1
        elif "evaluate" in code_ctx.lower() and "request" in code_ctx.lower():
            tp += 1
        elif cwe.startswith("CWE-"):
            tp += 1
        else:
            nr += 1
    return tp, fp, nr

# ── Run ──
loc, files = count_loc(repo_dir)
if loc == 0:
    print(json.dumps({"status": "no_files"}))
    sys.exit(0)

af, at = scan_ansede(repo_dir)
atp, afp, anr = audit(af, repo_dir)
sf, st = scan_sg(repo_dir)

print(json.dumps({
    "status": "ok",
    "loc": loc,
    "files": files,
    "ansede_n": len(af),
    "ansede_t": round(at, 1),
    "ansede_tp": atp,
    "ansede_fp": afp,
    "ansede_nr": anr,
    "sg_n": len(sf),
    "sg_t": round(st, 1),
}))
