"""Quick test of the production classifier on py-flask."""
import json, subprocess, sys

repo = "campaign/v2_100/repos/py-flask"
print(f"Scanning {repo}...")
r = subprocess.run(
    [sys.executable, "-m", "ansede_static.cli", repo, "--format", "json",
     "--fail-on", "never", "--max-file-kb", "200",
     "--exclude", "tests,test,node_modules"],
    capture_output=True, text=True, timeout=60,
)
data = json.loads(r.stdout)

from ansede_static.classifier import Classifier
from ansede_static._types import Finding, Severity

classifier = Classifier()
tp = fp = nr = 0

for entry in data.get("results", []):  # All files
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
        result = classifier.classify(finding, None, fname, "python")
        v = result.verdict.value
        if v == "LIKELY_TP":
            tp += 1
        elif v == "LIKELY_FP":
            fp += 1
        else:
            nr += 1
        print(f"  {v:12} c={result.confidence:.2f} | {fname}:{f.get('line')} {f.get('cwe','')} {f.get('title','')[:80]}")
        print(f"             -> {result.reason}")

print(f"\nTP={tp} FP={fp} NR={nr}")
total = tp + fp
if total:
    print(f"Precision: {round(tp/total*100,1)}%")
