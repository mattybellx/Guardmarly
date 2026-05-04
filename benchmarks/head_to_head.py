"""
benchmarks.head_to_head — Honest Ansede vs Semgrep OSS comparison on CVE corpus.

This is transparent, not cherry-picked. Every CVE in the corpus is tested
against both tools with their default/OSS rule sets. Results are reported
as-is, with caveats documented.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Any

# Ensure we can import ansede from the src directory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_code, _PYTHON_EXTS, _JS_EXTS
from benchmarks.cve_corpus import CVE_CORPUS


def _ext_to_lang(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in _PYTHON_EXTS:
        return "python"
    if ext in _JS_EXTS:
        return "javascript"
    return "unknown"


def run_ansede_on_snippet(cve_id: str, language: str, snippet: str) -> dict[str, Any]:
    """Run Ansede on a single snippet, return detection info."""
    # Determine filename extension
    ext = ".py" if language == "python" else ".js"

    result = scan_code(snippet, language=language, filename=f"{cve_id}{ext}")
    findings = result.findings

    unique_cwes = sorted(set(
        (f.cwe or "").strip().upper() for f in findings if (f.cwe or "").strip().upper().startswith("CWE-")
    ))
    unique_rules = sorted(set(f.rule_id for f in findings if f.rule_id))

    return {
        "tool": "ansede-static",
        "cve_id": cve_id,
        "language": language,
        "total_findings": len(findings),
        "detected_cwes": unique_cwes,
        "detected_rules": unique_rules,
        "detection_time_ms": 0,  # not measured at this granularity
        "error": None,
    }


def run_semgrep_on_snippet(cve_id: str, language: str, snippet: str) -> dict[str, Any]:
    """Run Semgrep OSS on a single snippet file, return detection info."""
    ext = ".py" if language == "python" else ".js"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=ext, prefix=f"{cve_id}_", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(snippet)
        tmp_path = Path(tmp.name)

    try:
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config=auto",
                "--no-git-ignore",
                "--quiet",
                "--json",
                str(tmp_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            env=env,
        )

        findings = []
        unique_cwes: set[str] = set()
        unique_rules: set[str] = set()
        error = None

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                results_list = data.get("results", [])
                for r in results_list:
                    findings.append(r)
                    extra = r.get("extra", {})
                    metadata = extra.get("metadata") or {}
                    cwe_list = metadata.get("cwe", [])
                    if isinstance(cwe_list, list):
                        for c in cwe_list:
                            c_str = str(c).strip().upper()
                            if ":" in c_str:
                                c_str = c_str.split(":")[0].strip()
                            if c_str.startswith("CWE-"):
                                unique_cwes.add(c_str)
                    rule_id = r.get("check_id", "")
                    if rule_id:
                        unique_rules.add(rule_id)
            except json.JSONDecodeError:
                error = f"Semgrep output parse error: {result.stdout[:200]}"
        elif result.returncode == 2:
            error = f"Semgrep fatal error: {result.stderr[:300]}"
        else:
            # returncode 1 = findings found (not an error)
            try:
                data = json.loads(result.stdout)
                results_list = data.get("results", [])
                for r in results_list:
                    findings.append(r)
                    extra = r.get("extra", {})
                    metadata = extra.get("metadata") or {}
                    cwe_list = metadata.get("cwe", [])
                    if isinstance(cwe_list, list):
                        for c in cwe_list:
                            c_str = str(c).strip().upper()
                            if ":" in c_str:
                                c_str = c_str.split(":")[0].strip()
                            if c_str.startswith("CWE-"):
                                unique_cwes.add(c_str)
                    rule_id = r.get("check_id", "")
                    if rule_id:
                        unique_rules.add(rule_id)
            except json.JSONDecodeError:
                error = f"Semgrep output parse error: {result.stdout[:200]}"

        return {
            "tool": "semgrep-oss",
            "cve_id": cve_id,
            "language": language,
            "total_findings": len(findings),
            "detected_cwes": sorted(unique_cwes),
            "detected_rules": sorted(unique_rules),
            "detection_time_ms": 0,
            "error": error,
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "semgrep-oss",
            "cve_id": cve_id,
            "language": language,
            "total_findings": 0,
            "detected_cwes": [],
            "detected_rules": [],
            "detection_time_ms": 0,
            "error": "Semgrep timed out (>120s)",
        }
    except FileNotFoundError:
        return {
            "tool": "semgrep-oss",
            "cve_id": cve_id,
            "language": language,
            "total_findings": 0,
            "detected_cwes": [],
            "detected_rules": [],
            "detection_time_ms": 0,
            "error": "Semgrep not installed",
        }
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def run_comparison() -> dict[str, Any]:
    """Run head-to-head comparison on all 35 CVEs."""

    results: list[dict[str, Any]] = []
    ansede_hits = 0
    ansede_misses: list[str] = []
    semgrep_hits = 0
    semgrep_misses: list[str] = []
    total = len(CVE_CORPUS)

    print(f"\n{'='*70}")
    print(f"  Ansede vs Semgrep OSS — Head-to-Head CVE Detection")
    print(f"  Corpus: {total} CVEs ({sum(1 for c in CVE_CORPUS if c.language == 'python')} Python, {sum(1 for c in CVE_CORPUS if c.language == 'javascript')} JavaScript)")
    print(f"{'='*70}\n")

    for i, cve_entry in enumerate(CVE_CORPUS, 1):
        cve_id = cve_entry.cve_id
        language = cve_entry.language
        snippet = cve_entry.snippet
        expected_cwe = (cve_entry.cwe or "").strip().upper()

        print(f"  [{i:2d}/{total}] {cve_id} ({language:>6} | expected {expected_cwe}) ... ", end="", flush=True)

        # Run Ansede
        ansede_result = run_ansede_on_snippet(cve_id, language, snippet)
        ansede_detected = expected_cwe in ansede_result["detected_cwes"] if expected_cwe else bool(ansede_result["detected_rules"])
        ansede_mark = "✅" if ansede_detected else "❌"
        if ansede_detected:
            ansede_hits += 1
        else:
            ansede_misses.append(cve_id)

        # Run Semgrep
        semgrep_result = run_semgrep_on_snippet(cve_id, language, snippet)
        semgrep_detected = expected_cwe in semgrep_result["detected_cwes"] if expected_cwe else bool(semgrep_result["detected_rules"])
        semgrep_mark = "✅" if semgrep_detected else "❌"
        if semgrep_detected:
            semgrep_hits += 1
        else:
            semgrep_misses.append(cve_id)

        print(f"Ansede {ansede_mark}  Semgrep {semgrep_mark}")

        results.append({
            "cve_id": cve_id,
            "language": language,
            "expected_cwe": expected_cwe,
            "ansede": ansede_result,
            "semgrep": semgrep_result,
            "ansede_detected": ansede_detected,
            "semgrep_detected": semgrep_detected,
        })

    ansede_recall = (ansede_hits / total * 100) if total else 0
    semgrep_recall = (semgrep_hits / total * 100) if total else 0

    print(f"\n{'='*70}")
    print(f"  RESULTS")
    print(f"{'='*70}")
    print(f"  Ansede-static  : {ansede_hits:2d}/{total} = {ansede_recall:.1f}% recall")
    print(f"  Semgrep OSS    : {semgrep_hits:2d}/{total} = {semgrep_recall:.1f}% recall")
    print(f"{'='*70}")

    if ansede_misses:
        print(f"\n  Ansede MISSED: {', '.join(ansede_misses)}")
    if semgrep_misses:
        print(f"\n  Semgrep MISSED: {', '.join(semgrep_misses)}")

    print(f"\n{'='*70}")
    print(f"  IMPORTANT CAVEATS")
    print(f"{'='*70}")
    print(textwrap.fill(
        "1. This corpus (35 CVEs) was designed by the Ansede author to test Ansede rules. "
        "It is NOT independent — Ansede has an inherent advantage. A fair benchmark requires "
        "a third-party curated corpus of 500+ CVEs neither tool was trained on.",
        width=66,
    ))
    print(textwrap.fill(
        "2. Semgrep OSS uses '--config=auto' which selects ~100 rules from the registry. "
        "Semgrep Pro/Team tiers have additional rules. CodeQL was not tested (requires CLI download).",
        width=66,
    ))
    print(textwrap.fill(
        "3. Detection = the expected CWE appears in the tool's findings. This is a minimum bar. "
        "It does not measure false positives, precision, or contextual accuracy.",
        width=66,
    ))
    print(textwrap.fill(
        "4. A real independent benchmark would use: (a) 500+ CVEs from NVD with reproducing snippets "
        "curated by a neutral party, (b) both true-positive recall AND false-positive rate measured "
        "on a 1M+ LOC corpus, (c) multiple judges to resolve disputed findings.",
        width=66,
    ))
    print()

    return {
        "corpus_size": total,
        "python_cves": sum(1 for c in CVE_CORPUS if c.language == "python"),
        "javascript_cves": sum(1 for c in CVE_CORPUS if c.language == "javascript"),
        "ansede": {
            "hits": ansede_hits,
            "misses": ansede_misses,
            "recall_pct": round(ansede_recall, 1),
        },
        "semgrep": {
            "hits": semgrep_hits,
            "misses": semgrep_misses,
            "recall_pct": round(semgrep_recall, 1),
        },
        "caveats": [
            "Corpus designed by Ansede author — Ansede has inherent advantage",
            "Semgrep OSS uses --config=auto (~100 rules) — Pro tier has more",
            "CodeQL not tested — requires separate CLI download and database build",
            "Detection = CWE match only — no FP rate measurement",
            "Not peer-reviewed — single-run comparison",
        ],
        "per_cve_results": results,
    }


if __name__ == "__main__":
    import time
    t0 = time.perf_counter()
    report = run_comparison()
    elapsed = time.perf_counter() - t0

    # Write JSON report
    out_path = Path("head_to_head_results.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Full results written to {out_path}")
    print(f"Total time: {elapsed:.1f}s")
