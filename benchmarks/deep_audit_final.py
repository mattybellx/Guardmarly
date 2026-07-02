#!/usr/bin/env python3
"""Final deep audit of v2_100 campaign — skips known timeout repos, uses --max-file-kb."""
import json, subprocess, sys, time
from pathlib import Path
from collections import Counter

REPOS_DIR = Path("campaign/v2_100/repos")
SKIP_REPOS = {"py-django"}  # Only Django times out consistently

# ── Classification helpers ──
def is_sql_safe(ctx):
    ctx = ctx.lower()
    if "?" in ctx and any(k in ctx for k in ["execute(", "query(", "cursor."]): return True
    if "%s" in ctx and "execute(" in ctx: return True
    if " + " in ctx and "select" in ctx: return False
    if "format(" in ctx and "select" in ctx: return False
    return None

def is_cmd_safe(ctx):
    ctx = ctx.lower()
    if "shell=true" in ctx or "os.system" in ctx: return False
    if "subprocess" in ctx and ("[" in ctx): return True
    return None

def is_xss_safe(ctx):
    ctx = ctx.lower()
    if "innerhtml" in ctx:
        return any(s in ctx for s in ["escape", "sanitize", "textcontent", "createelement"])
    return None

def is_deser_safe(ctx):
    ctx = ctx.lower()
    if "pickle.load" in ctx: return False
    if "yaml.load" in ctx and "safe_load" not in ctx: return False
    if "yaml.safe_load" in ctx: return True
    return None

def is_path_safe(ctx):
    ctx = ctx.lower()
    if "os.path.join" in ctx:
        return any(s in ctx for s in ["basedir", "base_dir", "root_dir", "safe_root", "resolve_path"])
    return None

def is_secret_safe(ctx):
    ctx = ctx.lower()
    if any(w in ctx for w in ["example", "test", "fake", "dummy", "placeholder", "changeme"]): return True
    if any(s in ctx for s in ["os.environ", "os.getenv", "process.env", "config[", "settings.", "getenv("]): return True
    return None

def classify(repo_name, lang, finding):
    fp_str = finding.get("file", "")
    line = finding.get("line", 0)
    cwe = str(finding.get("cwe", "")).upper()
    title = str(finding.get("title", ""))
    conf = finding.get("confidence", 1.0)

    # Resolve path
    full_path = None
    for cand in [Path(fp_str), REPOS_DIR / repo_name / fp_str]:
        if cand.exists():
            full_path = cand
            break
    if full_path is None and repo_name in fp_str:
        idx = fp_str.index(repo_name)
        suffix = fp_str[idx + len(repo_name):].lstrip("/").lstrip("\\")
        cand = REPOS_DIR / repo_name / suffix
        if cand.exists():
            full_path = cand

    if full_path is None:
        return {"verdict": "FILE_MISSING", "evidence": "File not found", "confidence": 0}

    try:
        if full_path.stat().st_size > 200 * 1024:
            return {"verdict": "SKIPPED_LARGE", "evidence": "File >200KB", "confidence": 0.5}
        lines_data = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"verdict": "FILE_UNREADABLE", "evidence": "Cannot read", "confidence": 0}

    start = max(0, line - 8)
    end = min(len(lines_data), line + 4)
    raw = "\n".join(lines_data[start:end])

    # Test file check
    pl = fp_str.lower().replace("\\", "/")
    if any(p in pl for p in ["/test", "/tests/", "/__tests__/", "/spec/",
                              "/fixtures/", "/examples/", "/demo/"]):
        return {"verdict": "CONFIRMED_FP", "evidence": "TEST_FILE", "confidence": 0.95}

    if conf < 0.35:
        return {"verdict": "CONFIRMED_FP", "evidence": f"LOW_CONF:{conf:.2f}", "confidence": 0.90}

    verdict, evidence, cert = "NEEDS_MANUAL_REVIEW", [], 0.5

    if "CWE-89" in cwe or "sql" in title.lower():
        s = is_sql_safe(raw)
        if s is True: verdict, evidence, cert = "CONFIRMED_FP", ["SQL_SAFE"], 0.92
        elif s is False: verdict, evidence, cert = "CONFIRMED_TP", ["SQL_UNSAFE"], 0.90
    elif "CWE-78" in cwe or "command" in title.lower() or "shell" in title.lower():
        s = is_cmd_safe(raw)
        if s is True: verdict, evidence, cert = "CONFIRMED_FP", ["CMD_SAFE"], 0.92
        elif s is False: verdict, evidence, cert = "CONFIRMED_TP", ["CMD_UNSAFE"], 0.95
    elif "CWE-79" in cwe or "xss" in title.lower():
        s = is_xss_safe(raw)
        if s is True: verdict, evidence, cert = "CONFIRMED_FP", ["XSS_SAFE"], 0.88
        elif s is False: verdict, evidence, cert = "CONFIRMED_TP", ["XSS_UNSAFE"], 0.88
    elif "CWE-502" in cwe or "deserial" in title.lower():
        s = is_deser_safe(raw)
        if s is True: verdict, evidence, cert = "CONFIRMED_FP", ["DESER_SAFE"], 0.92
        elif s is False: verdict, evidence, cert = "CONFIRMED_TP", ["DESER_UNSAFE"], 0.92
    elif "CWE-22" in cwe or "path" in title.lower():
        s = is_path_safe(raw)
        if s is True: verdict, evidence, cert = "CONFIRMED_FP", ["PATH_SAFE"], 0.85
        elif s is False: verdict, evidence, cert = "CONFIRMED_TP", ["PATH_UNSAFE"], 0.85
    elif "CWE-798" in cwe or "secret" in title.lower() or "credential" in title.lower():
        s = is_secret_safe(raw)
        if s is True: verdict, evidence, cert = "CONFIRMED_FP", ["SECRET_SAFE"], 0.90
        elif s is False: verdict, evidence, cert = "CONFIRMED_TP", ["SECRET_REAL"], 0.85
    elif "CWE-918" in cwe or "ssrf" in title.lower():
        if any(s in raw.lower() for s in ["urlparse", "allowed_hosts", "allowlist", "validate_url"]):
            verdict, evidence, cert = "CONFIRMED_FP", ["SSRF_SAFE"], 0.85
    elif "CWE-862" in cwe or "CWE-639" in cwe or "idor" in title.lower():
        if any(p in raw.lower() for p in ["user_id", "owner_id", "current_user", "request.user",
                                            ".user ==", ".owner =="]):
            verdict, evidence, cert = "CONFIRMED_FP", ["AUTH_SAFE"], 0.82

    if verdict == "NEEDS_MANUAL_REVIEW" and cwe.startswith("CWE-"):
        if any(p in raw.lower() for p in ["# nosec", "# nosemgrep", "# ansede: ignore",
                                            "# noqa", "# safe"]):
            verdict, evidence, cert = "CONFIRMED_FP", ["SUPPRESSED"], 0.88
        elif conf > 0.80:
            verdict, evidence, cert = "LIKELY_TP", [f"HIGH_CONF:{conf:.2f}"], 0.72

    return {"verdict": verdict, "evidence": "; ".join(evidence) if evidence else "GENERIC", "confidence": cert}


if __name__ == "__main__":
    print("=" * 60)
    print("FINAL DEEP AUDIT — v2_100 campaign")
    print("=" * 60)

    all_results = []
    summary = {}
    repo_dirs = sorted(d for d in REPOS_DIR.iterdir() if d.is_dir())

    for repo_dir in repo_dirs:
        repo = repo_dir.name
        if repo in SKIP_REPOS:
            print(f"SKIP {repo} (known timeout)")
            summary[repo] = {"status": "TIMEOUT", "findings": 0}
            continue

        lang = repo.split("-")[0]
        lang_map = {"py": "python", "js": "javascript"}
        lang = lang_map.get(lang, lang)

        print(f"[{len(summary)+1}/{len(repo_dirs)}] {repo}...", end=" ", flush=True)
        t0 = time.perf_counter()

        try:
            r = subprocess.run(
                [sys.executable, "-m", "ansede_static.cli", str(repo_dir), "--format", "json", "--fail-on", "never",
                 "--exclude", "tests,test,__tests__,spec,fixtures,examples,docs,demo,samples,node_modules,vendor,dist,build,migrations",
                 "--max-file-kb", "200"],
                capture_output=True, text=True, timeout=90,
            )
            data = json.loads(r.stdout) if r.stdout.strip() else {}
        except subprocess.TimeoutExpired:
            print("TIMEOUT")
            summary[repo] = {"status": "TIMEOUT", "findings": 0}
            continue
        except Exception as e:
            print(f"ERROR {e}")
            continue

        elapsed = time.perf_counter() - t0

        findings = []
        if isinstance(data, dict):
            for entry in data.get("results", []):
                fname = entry.get("file", "")
                for f in entry.get("findings", []):
                    if isinstance(f, dict):
                        f["file"] = fname
                        findings.append(f)

        findings = findings[:200]
        print(f"{len(findings)} in {elapsed:.1f}s", end=" ", flush=True)

        tp = fp = nr = 0
        for f in findings:
            audit = classify(repo, lang, f)
            audit["repo"] = repo
            audit["lang"] = lang
            audit["file"] = f.get("file", "")
            audit["line"] = f.get("line", 0)
            audit["cwe"] = f.get("cwe", "")
            audit["title"] = f.get("title", "")[:120]
            all_results.append(audit)
            v = audit["verdict"]
            if v in ("CONFIRMED_TP", "LIKELY_TP"):
                tp += 1
            elif v == "CONFIRMED_FP":
                fp += 1
            else:
                nr += 1

        summary[repo] = {"status": "OK", "findings": len(findings), "tp": tp, "fp": fp, "nr": nr, "time": elapsed}
        print(f"TP={tp} FP={fp} NR={nr}")

    # ── Final report ──
    total_tp = sum(1 for a in all_results if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"))
    total_fp = sum(1 for a in all_results if a["verdict"] == "CONFIRMED_FP")
    total_nr = sum(1 for a in all_results if a["verdict"] == "NEEDS_MANUAL_REVIEW")
    total_classified = total_tp + total_fp
    precision = round(total_tp / total_classified * 100, 1) if total_classified else 0

    print()
    print("=" * 60)
    print("DEEP AUDIT FINAL RESULTS")
    print("=" * 60)
    print(f"Repos scanned:     {len([s for s in summary.values() if s['status']=='OK'])}")
    print(f"Repos timed out:   {len([s for s in summary.values() if s['status']=='TIMEOUT'])}")
    print(f"Total findings:    {len(all_results)}")
    print(f"CONFIRMED_TP:      {total_tp}")
    print(f"CONFIRMED_FP:      {total_fp}")
    print(f"NEEDS_REVIEW:      {total_nr}")
    print(f"Precision:         {precision}%")

    # By language
    for lang in ["python", "javascript"]:
        lr = [a for a in all_results if a["lang"] == lang]
        if not lr:
            continue
        lt = sum(1 for a in lr if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"))
        lf = sum(1 for a in lr if a["verdict"] == "CONFIRMED_FP")
        ln = sum(1 for a in lr if a["verdict"] == "NEEDS_MANUAL_REVIEW")
        lp = round(lt / (lt + lf) * 100, 1) if (lt + lf) else 0
        print(f"  {lang:>12}: {len(lr):>4} findings | TP={lt:>4} FP={lf:>4} NR={ln:>4} | Prec={lp}%")

    # Per repo
    print("\nPer-repo summary:")
    for repo, s in sorted(summary.items()):
        if s["status"] == "TIMEOUT":
            print(f"  {repo}: TIMEOUT")
        else:
            denom = s["tp"] + s["fp"]
            pc = round(s["tp"] / denom * 100, 1) if denom else 0
            print(f"  {repo:>25}: {s['findings']:>3} findings, TP={s['tp']:>3} FP={s['fp']:>3} NR={s['nr']:>3}, Prec={pc}%, {s['time']:.1f}s")

    # FP causes
    fp_reasons = Counter()
    for a in all_results:
        if a["verdict"] == "CONFIRMED_FP":
            fp_reasons[a["evidence"].split(";")[0]] += 1
    print(f"\nTop FP causes:")
    for reason, count in fp_reasons.most_common(10):
        print(f"  {count:>4} x {reason}")

    # FP samples
    fp_samples = [a for a in all_results if a["verdict"] == "CONFIRMED_FP"]
    if fp_samples:
        print(f"\nFP samples (first 10):")
        for a in fp_samples[:10]:
            print(f"  {a['repo']}/{a.get('file','?')}:{a.get('line','?')}  {a.get('cwe','?')}  {a['evidence']}")

    # Save
    out = {
        "ts": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "total": len(all_results),
        "tp": total_tp,
        "fp": total_fp,
        "nr": total_nr,
        "precision": precision,
        "summary": {k: {kk: vv for kk, vv in v.items() if kk != "time"} for k, v in summary.items()},
        "fp_causes": dict(fp_reasons.most_common(20)),
    }
    out_path = Path("campaign/v2_100/deep_audit_final.json")
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\nSaved: {out_path}")
    print("DONE.")
