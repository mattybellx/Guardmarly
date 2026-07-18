"""CI helper: convert guardmarly JSON output to SARIF using the built-in formatter."""
import json
from guardmarly._types import AnalysisResult, Finding, Severity
from guardmarly.reporters import format_sarif

with open("guardmarly.json") as fh:
    data = json.load(fh)

results = []
for entry in data.get("results", []):
    r = AnalysisResult(file_path=entry.get("file_path", ""), language=entry.get("language", ""))
    for f in entry.get("findings", []):
        sev = getattr(Severity, f.get("severity", "INFO").upper(), Severity.INFO)
        finding = Finding(
            category=f.get("category", "security"),
            severity=sev,
            title=f.get("title", ""),
            description=f.get("description", ""),
            line=f.get("line"),
            rule_id=f.get("rule_id", ""),
            cwe=f.get("cwe", ""),
            confidence=f.get("confidence", 0.5),
            agent=f.get("agent", ""),
            analysis_kind=f.get("analysis_kind", "pattern"),
        )
        r.findings.append(finding)
    results.append(r)

sarif = format_sarif(results)
with open("guardmarly.sarif", "w") as fh:
    fh.write(sarif)
print(f"Generated SARIF with {len(results)} file(s)")
