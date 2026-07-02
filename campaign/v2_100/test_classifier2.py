"""Test classifier on a real application repo."""
import json, subprocess, sys

repos = ["campaign/v2_100/repos/py-rich", "campaign/v2_100/repos/js-axios"]
from ansede_static.classifier import Classifier
from ansede_static._types import Finding, Severity

classifier = Classifier()

for repo in repos:
    print(f"\n=== {repo} ===")
    r = subprocess.run(
        [sys.executable, "-m", "ansede_static.cli", repo, "--format", "json",
         "--fail-on", "never", "--max-file-kb", "200",
         "--exclude", "tests,test,node_modules,examples,docs"],
        capture_output=True, text=True, timeout=60,
    )
    data = json.loads(r.stdout)
    tp = fp = nr = 0
    samples = {"TP": [], "FP": [], "NR": []}
    for entry in data.get("results", []):
        fname = entry.get("file", "")
        for f in entry.get("findings", []):
            finding = Finding(
                category="security",
                severity=Severity(f.get("severity", "medium")),
                title=f.get("title", ""),
                description=f.get("description", ""),
                line=f.get("line"),
                rule_id=f.get("rule_id", ""),
                cwe=f.get("cwe", ""),
                confidence=float(f.get("confidence", 0.5)),
                analysis_kind=f.get("analysis_kind", "pattern"),
            )
            result = classifier.classify(finding, None, fname, "python" if "py" in repo else "javascript")
            v = result.verdict.value
            if v == "LIKELY_TP":
                tp += 1
                if len(samples["TP"]) < 3:
                    samples["TP"].append(f"{fname}:{f.get('line')} {f.get('cwe','')} {f.get('title','')[:80]}")
            elif v == "LIKELY_FP":
                fp += 1
                if len(samples["FP"]) < 3:
                    samples["FP"].append(f"{fname}:{f.get('line')} {f.get('cwe','')} {f.get('title','')[:80]}")
            else:
                nr += 1
                if len(samples["NR"]) < 3:
                    samples["NR"].append(f"{fname}:{f.get('line')} {f.get('cwe','')} {f.get('title','')[:80]}")

    print(f"TP={tp} FP={fp} NR={nr}")
    if tp + fp:
        print(f"Precision: {round(tp/(tp+fp)*100,1)}%")
    for k, v in samples.items():
        if v:
            print(f"  {k} samples:")
            for s in v:
                print(f"    {s}")
