#!/usr/bin/env python3
"""Deep audit v2 — uses production classifier instead of naive string matching."""
import json, subprocess, sys, time
from pathlib import Path

REPOS_DIR = Path("campaign/v2_100/repos")
SKIP_REPOS = {"py-django"}


def classify_findings(findings: list[dict], source_code: str, file_path: str, language: str):
    """Use the production classifier on a batch of findings."""
    from ansede_static._types import Finding, Severity
    from ansede_static.classifier import Classifier, Verdict

    classifier = Classifier()
    source_lines = source_code.splitlines() if source_code else None

    results = []
    for f in findings:
        # Convert dict to Finding
        finding = Finding(
            category="security",
            severity=Severity(f.get("severity", "medium")),
            title=f.get("title", ""),
            description=f.get("description", ""),
            line=f.get("line"),
            rule_id=f.get("rule_id", ""),
            cwe=f.get("cwe", ""),
            agent=f.get("agent", ""),
            confidence=float(f.get("confidence", 0.5)),
            analysis_kind=f.get("analysis_kind", "pattern"),
            triggering_code=f.get("triggering_code", ""),
        )

        result = classifier.classify(finding, source_lines, file_path, language)
        results.append({
            "verdict": result.verdict.value,
            "confidence": result.confidence,
            "reason": result.reason,
            "line": f.get("line"),
            "cwe": f.get("cwe", ""),
            "title": f.get("title", "")[:120],
            "rule_id": f.get("rule_id", ""),
        })

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("DEEP AUDIT v2 — Production Classifier")
    print("=" * 60)

    all_results = []
    summary = {}
    repo_dirs = sorted(d for d in REPOS_DIR.iterdir() if d.is_dir())

    for i, repo_dir in enumerate(repo_dirs):
        repo = repo_dir.name
        if repo in SKIP_REPOS:
            print(f"SKIP {repo} (known timeout)")
            summary[repo] = {"status": "SKIP", "findings": 0}
            continue

        lang_code = repo.split("-")[0]
        lang_map = {"py": "python", "js": "javascript"}
        language = lang_map.get(lang_code, lang_code)

        print(f"[{i+1}/{len(repo_dirs)}] {repo}...", end=" ", flush=True)
        t0 = time.perf_counter()

        try:
            r = subprocess.run(
                [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
                 "--format", "json", "--fail-on", "never",
                 "--timeout-per-file", "15",
                 "--exclude", "tests,test,__tests__,spec,fixtures,examples,docs,demo,samples,node_modules,vendor,dist,build,migrations",
                 "--max-file-kb", "200"],
                capture_output=True, text=True, timeout=120,
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

        # Extract findings
        findings = []
        if isinstance(data, dict):
            for entry in data.get("results", []):
                fname = entry.get("file", "")
                code = entry.get("code", "") or entry.get("source", "") or ""
                lang = entry.get("language", language)
                for f in entry.get("findings", []):
                    if isinstance(f, dict):
                        f["_file"] = fname
                        f["_code"] = code
                        f["_lang"] = lang
                        findings.append(f)

        findings = findings[:200]  # Cap per repo
        print(f"{len(findings)} in {elapsed:.1f}s", end=" ", flush=True)

        # Classify each finding using the production classifier
        tp = fp = nr = 0
        from ansede_static.classifier import Classifier
        classifier = Classifier()

        for f in findings:
            file_path = f.get("_file", "")
            source_code = f.get("_code", "")
            lang = f.get("_lang", language)
            source_lines = source_code.splitlines() if source_code else None

            from ansede_static._types import Finding, Severity
            finding_obj = Finding(
                category="security",
                severity=Severity(f.get("severity", "medium")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                line=f.get("line"),
                rule_id=f.get("rule_id", ""),
                cwe=f.get("cwe", ""),
                agent=f.get("agent", ""),
                confidence=float(f.get("confidence", 0.5)),
                analysis_kind=f.get("analysis_kind", "pattern"),
                triggering_code=f.get("triggering_code", ""),
            )

            result = classifier.classify(finding_obj, source_lines, file_path, lang)
            result_dict = {
                "repo": repo,
                "file": file_path,
                "line": f.get("line"),
                "cwe": f.get("cwe", ""),
                "title": f.get("title", "")[:120],
                "verdict": result.verdict.value,
                "confidence": result.confidence,
                "reason": result.reason,
            }
            all_results.append(result_dict)

            v = result.verdict.value
            if v == "LIKELY_TP":
                tp += 1
            elif v == "LIKELY_FP":
                fp += 1
            else:
                nr += 1

        summary[repo] = {"status": "OK", "findings": len(findings), "tp": tp, "fp": fp, "nr": nr, "time": elapsed}
        denom = tp + fp
        pct = round(tp / denom * 100, 1) if denom else 0
        print(f"TP={tp} FP={fp} NR={nr} Prec={pct}%")

    # ── Final report ──
    total_tp = sum(1 for a in all_results if a["verdict"] == "LIKELY_TP")
    total_fp = sum(1 for a in all_results if a["verdict"] == "LIKELY_FP")
    total_nr = sum(1 for a in all_results if a["verdict"] == "NEEDS_REVIEW")
    total_classified = total_tp + total_fp
    precision = round(total_tp / total_classified * 100, 1) if total_classified else 0

    print()
    print("=" * 60)
    print("DEEP AUDIT v2 FINAL RESULTS")
    print(f"  Findings: {len(all_results)}")
    print(f"  TP: {total_tp}  FP: {total_fp}  NR: {total_nr}")
    print(f"  Precision: {precision}%")
    print(f"  Auto-classified: {round((total_tp+total_fp)/len(all_results)*100,1) if all_results else 0}%")
    print()

    # Per repo
    print("Per-repo summary:")
    for repo, s in sorted(summary.items()):
        if s["status"] != "OK":
            print(f"  {repo:>25}: {s['status']}")
        else:
            denom = s["tp"] + s["fp"]
            pc = round(s["tp"] / denom * 100, 1) if denom else 0
            print(f"  {repo:>25}: {s['findings']:>3} findings, TP={s['tp']:>3} FP={s['fp']:>3} NR={s['nr']:>2}, Prec={pc}%")

    # Save
    from datetime import datetime, timezone
    out = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "classifier": "production-v2",
        "total": len(all_results),
        "tp": total_tp,
        "fp": total_fp,
        "nr": total_nr,
        "precision": precision,
        "auto_classified_pct": round((total_tp + total_fp) / len(all_results) * 100, 1) if all_results else 0,
        "summary": {k: {kk: vv for kk, vv in v.items() if kk != "time"} for k, v in summary.items()},
    }
    out_path = Path("campaign/v2_100/deep_audit_v2.json")
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\nSaved: {out_path}")
    print("DONE.")
